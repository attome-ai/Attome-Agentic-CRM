//! Email address checks (roadmap E6-T6), the parts that need no network:
//! syntax within the RFC 5321 length limits, role addresses, the shipped
//! disposable-domain list and typo suggestions for the large providers. The
//! MX lookup and the record validator that uses these checks build on
//! [`check_address_offline`].
//!
//! Only a syntax error makes an address invalid; the other findings make it
//! risky, so a form or import warns instead of refusing.

use std::collections::HashSet;
use std::sync::LazyLock;

/// The longest address (RFC 5321 path limit less the angle brackets).
pub const MAX_ADDRESS: usize = 254;
/// The longest local part.
pub const MAX_LOCAL: usize = 64;

static DISPOSABLE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../data/disposable_domains.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

const ROLE_LOCALS: &[&str] = &[
    "info", "sales", "admin", "support", "noreply", "no-reply", "contact", "hello",
];

const TYPO_TARGETS: &[&str] = &[
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
];

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressIssue {
    Empty,
    TooLong,
    LocalTooLong,
    NotOneAt,
    BadLocal,
    BadDomain,
    RoleAddress,
    DisposableDomain,
    LikelyTypo,
    NoMx,
}

/// The overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressStatus {
    Valid,
    Risky,
    Invalid,
}

/// The result of checking one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCheck {
    pub status: AddressStatus,
    pub issues: Vec<AddressIssue>,
    /// A corrected address when the domain looks like a typo.
    pub suggestion: Option<String>,
}

/// Syntax only: lengths, exactly one `@`, a sane local part and a domain
/// with at least one dot and no empty labels.
pub fn check_syntax(address: &str) -> Result<(), AddressIssue> {
    let address = address.trim();
    if address.is_empty() {
        return Err(AddressIssue::Empty);
    }
    if address.len() > MAX_ADDRESS {
        return Err(AddressIssue::TooLong);
    }
    let mut parts = address.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(AddressIssue::NotOneAt);
    };
    if local.len() > MAX_LOCAL {
        return Err(AddressIssue::LocalTooLong);
    }
    let local_ok = !local.is_empty()
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~.-".contains(c));
    if !local_ok {
        return Err(AddressIssue::BadLocal);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !domain_ok {
        return Err(AddressIssue::BadDomain);
    }
    Ok(())
}

/// Whether the local part is a shared role mailbox.
pub fn is_role_address(local: &str) -> bool {
    let local = local.to_ascii_lowercase();
    ROLE_LOCALS.contains(&local.as_str())
}

/// Whether `domain` is on the shipped disposable list.
pub fn is_disposable(domain: &str) -> bool {
    DISPOSABLE.contains(domain.to_ascii_lowercase().as_str())
}

/// The large provider `domain` is one or two edits away from, if any.
pub fn typo_suggestion(domain: &str) -> Option<&'static str> {
    let domain = domain.to_ascii_lowercase();
    if TYPO_TARGETS.contains(&domain.as_str()) {
        return None;
    }
    TYPO_TARGETS
        .iter()
        .map(|t| (*t, edit_distance(&domain, t)))
        .filter(|(_, d)| (1..=2).contains(d))
        .min_by_key(|(_, d)| *d)
        .map(|(t, _)| t)
}

/// Levenshtein distance with adjacent transpositions (optimal string
/// alignment), so "gmial" is one edit from "gmail".
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

/// Every check that needs no network. `has_mx` is the caller's DNS answer
/// for the domain when it has one (`None` when not looked up).
pub fn check_address_offline(address: &str, has_mx: Option<bool>) -> AddressCheck {
    if let Err(issue) = check_syntax(address) {
        return AddressCheck {
            status: AddressStatus::Invalid,
            issues: vec![issue],
            suggestion: None,
        };
    }
    let address = address.trim();
    let (local, domain) = address.rsplit_once('@').unwrap_or((address, ""));
    let mut issues = Vec::new();
    if is_role_address(local) {
        issues.push(AddressIssue::RoleAddress);
    }
    let disposable = is_disposable(domain);
    if disposable {
        issues.push(AddressIssue::DisposableDomain);
    }
    // A known disposable domain is spelled as meant, not a typo.
    let suggestion = if disposable {
        None
    } else {
        typo_suggestion(domain).map(|d| format!("{local}@{d}"))
    };
    if suggestion.is_some() {
        issues.push(AddressIssue::LikelyTypo);
    }
    if has_mx == Some(false) {
        issues.push(AddressIssue::NoMx);
    }
    AddressCheck {
        status: if issues.is_empty() {
            AddressStatus::Valid
        } else {
            AddressStatus::Risky
        },
        issues,
        suggestion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_rules() {
        assert_eq!(check_syntax("a.b+tag@example.co.sa"), Ok(()));
        assert_eq!(check_syntax(""), Err(AddressIssue::Empty));
        assert_eq!(check_syntax("a@b@c.com"), Err(AddressIssue::NotOneAt));
        assert_eq!(
            check_syntax("a..b@example.com"),
            Err(AddressIssue::BadLocal)
        );
        assert_eq!(check_syntax("a@localhost"), Err(AddressIssue::BadDomain));
        assert_eq!(
            check_syntax(&format!("{}@example.com", "a".repeat(65))),
            Err(AddressIssue::LocalTooLong)
        );
    }

    #[test]
    fn role_addresses_are_risky_not_invalid() {
        let c = check_address_offline("Info@acme.sa", None);
        assert_eq!(c.status, AddressStatus::Risky);
        assert_eq!(c.issues, vec![AddressIssue::RoleAddress]);
    }

    #[test]
    fn disposable_domains_are_flagged() {
        assert!(is_disposable("Mailinator.com"));
        let c = check_address_offline("x@yopmail.com", Some(true));
        assert_eq!(c.issues, vec![AddressIssue::DisposableDomain]);
    }

    #[test]
    fn gmial_suggests_gmail() {
        let c = check_address_offline("sara@gmial.com", None);
        assert_eq!(c.suggestion.as_deref(), Some("sara@gmail.com"));
        assert!(c.issues.contains(&AddressIssue::LikelyTypo));
        assert_eq!(typo_suggestion("gmail.com"), None);
        assert_eq!(typo_suggestion("example.com"), None);
    }

    #[test]
    fn no_mx_is_risky_and_a_clean_address_is_valid() {
        assert_eq!(
            check_address_offline("a@acme.sa", Some(false)).issues,
            vec![AddressIssue::NoMx]
        );
        assert_eq!(
            check_address_offline("a@acme.sa", Some(true)).status,
            AddressStatus::Valid
        );
    }
}

//! Mailbox providers (roadmap E6-T4): which provider hosts a recipient's
//! domain, so deliverability can be read per provider (Gmail filters
//! differently from Outlook). A fixed table of the large providers and the
//! regional ones common in the Gulf; everything else is `Other`.

/// The provider behind a recipient domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MailboxProvider {
    Gmail,
    Outlook,
    Yahoo,
    Icloud,
    /// A regional provider, by name.
    Regional(String),
    Other,
}

impl MailboxProvider {
    /// A stable key for storage and reports.
    pub fn key(&self) -> String {
        match self {
            Self::Gmail => "gmail".into(),
            Self::Outlook => "outlook".into(),
            Self::Yahoo => "yahoo".into(),
            Self::Icloud => "icloud".into(),
            Self::Regional(name) => format!("regional:{name}"),
            Self::Other => "other".into(),
        }
    }
}

const GMAIL: &[&str] = &["gmail.com", "googlemail.com"];
const OUTLOOK: &[&str] = &[
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "outlook.sa",
    "hotmail.co.uk",
];
const YAHOO: &[&str] = &["yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk"];
const ICLOUD: &[&str] = &["icloud.com", "me.com", "mac.com"];
const REGIONAL: &[(&str, &str)] = &[
    ("stc.com.sa", "stc"),
    ("sahara.com.sa", "sahara"),
    ("etisalat.ae", "etisalat"),
    ("emirates.net.ae", "etisalat"),
    ("eim.ae", "etisalat"),
    ("du.ae", "du"),
    ("qatar.net.qa", "ooredoo"),
    ("omantel.net.om", "omantel"),
    ("batelco.com.bh", "batelco"),
    ("tedata.net.eg", "te_data"),
];

/// Classifies `domain` (case and a trailing dot ignored).
pub fn classify(domain: &str) -> MailboxProvider {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let is = |list: &[&str]| list.iter().any(|d| *d == domain);
    if is(GMAIL) {
        MailboxProvider::Gmail
    } else if is(OUTLOOK) {
        MailboxProvider::Outlook
    } else if is(YAHOO) {
        MailboxProvider::Yahoo
    } else if is(ICLOUD) {
        MailboxProvider::Icloud
    } else if let Some((_, name)) = REGIONAL.iter().find(|(d, _)| *d == domain) {
        MailboxProvider::Regional((*name).to_owned())
    } else {
        MailboxProvider::Other
    }
}

/// Classifies the domain of an address; no `@` is `Other`.
pub fn classify_address(address: &str) -> MailboxProvider {
    address
        .rsplit_once('@')
        .map_or(MailboxProvider::Other, |(_, domain)| classify(domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_domains() {
        assert_eq!(classify("gmail.com"), MailboxProvider::Gmail);
        assert_eq!(classify("GoogleMail.com."), MailboxProvider::Gmail);
        assert_eq!(classify("hotmail.com"), MailboxProvider::Outlook);
        assert_eq!(classify("yahoo.com"), MailboxProvider::Yahoo);
        assert_eq!(classify("me.com"), MailboxProvider::Icloud);
        assert_eq!(
            classify("stc.com.sa"),
            MailboxProvider::Regional("stc".into())
        );
        assert_eq!(classify("etisalat.ae").key(), "regional:etisalat");
        assert_eq!(classify("example.org"), MailboxProvider::Other);
        assert_eq!(
            classify_address("a.b@Outlook.com"),
            MailboxProvider::Outlook
        );
        assert_eq!(classify_address("no-at-sign"), MailboxProvider::Other);
    }
}

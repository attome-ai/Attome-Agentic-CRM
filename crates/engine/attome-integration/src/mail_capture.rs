//! D15-T2: which emails from a person's own mailbox are captured, and onto
//! which addresses (the runner that writes them is the app's
//! `mail_capture` job).
//!
//! A message is captured when it is not marked private, not a draft, not an
//! automatic or bulk message, and has a `Message-ID` (the key that keeps it
//! from being captured twice, whoever's mailbox it is read from). The
//! addresses it is captured onto are everyone on it except the person
//! themselves and anyone at an excluded domain (`mail_capture.
//! excluded_domains`, typically the company's own domains, so internal mail
//! stays out).

use crate::connector::adapters::mail::MailMessage;

/// A domain list from a setting: comma, semicolon or space separated, each
/// lower-cased, with any leading `@`. Pure.
pub fn domain_list(raw: &str) -> Vec<String> {
    raw.split([',', ';', ' ', '\n', '\t'])
        .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect()
}

/// Whether `address` is at `domain` or one of its subdomains. Pure.
fn at_domain(address: &str, domain: &str) -> bool {
    address
        .rsplit_once('@')
        .is_some_and(|(_, d)| d == domain || d.ends_with(&format!(".{domain}")))
}

/// Whether a message may be captured at all. Pure.
pub fn capturable(message: &MailMessage) -> bool {
    let automatic = message
        .auto_submitted
        .as_deref()
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("no"));
    let bulk = message.precedence.as_deref().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "bulk" | "list" | "junk"
        )
    });
    !message.private
        && !automatic
        && !bulk
        && message.list_id.is_none()
        && message.message_id.is_some()
}

/// The addresses the message is captured onto: everyone on it but `own` and
/// the excluded domains, lower-cased, each once. Pure.
pub fn external_addresses(message: &MailMessage, own: &str, excluded: &[String]) -> Vec<String> {
    let own = own.trim().to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    for a in message.from.iter().chain(&message.to).chain(&message.cc) {
        let address = a.address.trim().to_ascii_lowercase();
        if address.is_empty()
            || !address.contains('@')
            || address == own
            || excluded.iter().any(|d| at_domain(&address, d))
            || out.contains(&address)
        {
            continue;
        }
        out.push(address);
    }
    out
}

/// `outbound` when the person sent it, else `inbound`. Pure.
pub fn direction(message: &MailMessage, own: &str) -> &'static str {
    let sent = message
        .from
        .as_ref()
        .is_some_and(|f| f.address.trim().eq_ignore_ascii_case(own.trim()));
    if sent { "outbound" } else { "inbound" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::adapters::mail::MailAddress;

    fn addr(a: &str) -> MailAddress {
        MailAddress {
            name: None,
            address: a.into(),
        }
    }

    fn message() -> MailMessage {
        MailMessage {
            provider: "graph",
            id: "1".into(),
            message_id: Some("m1@client.sa".into()),
            from: Some(addr("Sara@Client.sa")),
            to: vec![addr("me@us.sa"), addr("ops@us.sa")],
            cc: vec![addr("cfo@client.sa"), addr("sara@client.sa")],
            ..MailMessage::default()
        }
    }

    #[test]
    fn mail_capture_matches_external_addresses_once() {
        let excluded = domain_list("@us.sa; partner.example");
        assert_eq!(excluded, vec!["us.sa", "partner.example"]);
        assert_eq!(
            external_addresses(&message(), "me@us.sa", &excluded),
            vec!["sara@client.sa", "cfo@client.sa"]
        );
        assert_eq!(direction(&message(), "me@us.sa"), "inbound");
        let sent = MailMessage {
            from: Some(addr("ME@us.sa")),
            ..message()
        };
        assert_eq!(direction(&sent, "me@us.sa"), "outbound");
        assert!(at_domain("a@mail.us.sa", "us.sa"));
        assert!(!at_domain("a@notus.sa", "us.sa"));
    }

    #[test]
    fn mail_capture_skips_private_automatic_and_bulk_mail() {
        assert!(capturable(&message()));
        assert!(!capturable(&MailMessage {
            private: true,
            ..message()
        }));
        assert!(!capturable(&MailMessage {
            auto_submitted: Some("auto-replied".into()),
            ..message()
        }));
        assert!(capturable(&MailMessage {
            auto_submitted: Some("no".into()),
            ..message()
        }));
        assert!(!capturable(&MailMessage {
            precedence: Some("Bulk".into()),
            ..message()
        }));
        assert!(!capturable(&MailMessage {
            list_id: Some("<news.example>".into()),
            ..message()
        }));
        assert!(
            !capturable(&MailMessage {
                message_id: None,
                ..message()
            }),
            "no id, no dedupe"
        );
    }
}

//! Portal email templates (web-portal plan Phase 7, G-12): the account emails
//! a portal sends carry **the portal's name**, not the staff product's
//! wording, so a customer recognises who is writing. Each returns
//! `(subject, text_body, html_body)`, like `attome_email::templates`.
//!
//! The portal name is admin-entered text: it is cleaned of control
//! characters (and length-capped) before it goes into a subject line, and
//! HTML-escaped in the HTML body. A link is escaped only where it sits in an
//! HTML attribute; the text body keeps the raw URL a mail client linkifies.
//! Every link is already a portal-host URL (`router::portal_base_url`, T-34).

use attome_email::templates::escape_html;

/// Longest portal name a subject line carries.
const MAX_NAME_CHARS: usize = 80;

/// The portal's name as it may appear in a subject: control characters
/// (line breaks included) become spaces, runs of whitespace collapse, and
/// it is capped. An empty result falls back to a neutral phrase.
fn display_name(portal_name: &str) -> String {
    let cleaned: String = portal_name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let capped: String = collapsed.chars().take(MAX_NAME_CHARS).collect();
    if capped.is_empty() {
        "your portal".to_owned()
    } else {
        capped
    }
}

/// An invitation to set up an account on the portal.
pub fn invitation(portal_name: &str, link: &str) -> (String, String, String) {
    let name = display_name(portal_name);
    let subject = format!("You've been invited to {name}");
    let text = format!(
        "You've been invited to create an account on {name}.\n\n\
         Set up your account here (this link expires soon): {link}\n\n\
         If you weren't expecting this, you can safely ignore this email."
    );
    let html = format!(
        "<p>You've been invited to create an account on <strong>{n}</strong>.</p>\
         <p><a href=\"{l}\">Set up your account</a> (this link expires soon)</p>\
         <p>If you weren't expecting this, you can safely ignore this email.</p>",
        n = escape_html(&name),
        l = escape_html(link),
    );
    (subject, text, html)
}

/// A password reset for the user's account on the portal.
pub fn password_reset(portal_name: &str, link: &str) -> (String, String, String) {
    let name = display_name(portal_name);
    let subject = format!("Reset your {name} password");
    let text = format!(
        "We received a request to reset your password for {name}.\n\n\
         Reset it here (this link expires soon): {link}\n\n\
         If you didn't request this, you can safely ignore this email; your \
         password will not be changed."
    );
    let html = format!(
        "<p>We received a request to reset your password for <strong>{n}</strong>.</p>\
         <p><a href=\"{l}\">Reset your password</a> (this link expires soon)</p>\
         <p>If you didn't request this, you can safely ignore this email; your \
         password will not be changed.</p>",
        n = escape_html(&name),
        l = escape_html(link),
    );
    (subject, text, html)
}

/// The address check that completes a self-service signup.
pub fn email_verification(portal_name: &str, link: &str) -> (String, String, String) {
    let name = display_name(portal_name);
    let subject = format!("Verify your email for {name}");
    let text = format!(
        "Please verify your email address to finish setting up your account on {name}.\n\n\
         Verify here: {link}\n\n\
         If you didn't sign up, you can safely ignore this email."
    );
    let html = format!(
        "<p>Please verify your email address to finish setting up your account on \
         <strong>{n}</strong>.</p>\
         <p><a href=\"{l}\">Verify your email</a></p>\
         <p>If you didn't sign up, you can safely ignore this email.</p>",
        n = escape_html(&name),
        l = escape_html(link),
    );
    (subject, text, html)
}

/// D-780: the check that adds this address to an existing account (asked for
/// in a game or another trusted client).
pub fn email_add_verification(portal_name: &str, link: &str) -> (String, String, String) {
    let name = display_name(portal_name);
    let subject = format!("Confirm your email for {name}");
    let text = format!(
        "You asked to add this email address to your {name} account, so you can \
         reset your password if you ever forget it.\n\n\
         Confirm it here (this link expires in 24 hours): {link}\n\n\
         If this wasn't you, ignore this email; nothing changes."
    );
    let html = format!(
        "<p>You asked to add this email address to your <strong>{n}</strong> account, so \
         you can reset your password if you ever forget it.</p>\
         <p><a href=\"{l}\">Confirm your email</a> (this link expires in 24 hours)</p>\
         <p>If this wasn't you, ignore this email; nothing changes.</p>",
        n = escape_html(&name),
        l = escape_html(link),
    );
    (subject, text, html)
}

/// A short account notice from the portal: `"{name}: {headline}"` as the
/// subject, `body` as one paragraph. `headline` and `body` are this crate's
/// own fixed wording, never user input.
pub fn notice(portal_name: &str, headline: &str, body: &str) -> (String, String, String) {
    let name = display_name(portal_name);
    let subject = format!("{name}: {headline}");
    let html = format!(
        "<p><strong>{n}</strong></p><p>{b}</p>",
        n = escape_html(&name),
        b = escape_html(body),
    );
    (subject, body.to_owned(), html)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "https://portal.example.com/acme/reset-password?token=a&b=\"c\"";

    #[test]
    fn every_template_names_the_portal() {
        for (subject, text, html) in [
            invitation("Acme Support", LINK),
            password_reset("Acme Support", LINK),
            email_verification("Acme Support", LINK),
            notice("Acme Support", "a recovery code was used", "Body."),
        ] {
            assert!(subject.contains("Acme Support"), "{subject}");
            assert!(html.contains("Acme Support"), "{html}");
            assert!(!text.is_empty());
        }
    }

    #[test]
    fn a_hostile_portal_name_cannot_break_the_subject_or_the_html() {
        let hostile = "Acme\r\nBcc: victim@example.com <script>alert(1)</script>";
        for (subject, _, html) in [
            invitation(hostile, LINK),
            password_reset(hostile, LINK),
            email_verification(hostile, LINK),
            notice(hostile, "headline", "body"),
        ] {
            assert!(
                !subject.contains('\r') && !subject.contains('\n'),
                "no header injection: {subject:?}"
            );
            assert!(!html.contains("<script>"), "escaped in HTML: {html}");
            assert!(html.contains("&lt;script&gt;"), "{html}");
        }
    }

    #[test]
    fn the_link_is_escaped_only_inside_the_html_attribute() {
        let (_, text, html) = password_reset("Acme", LINK);
        assert!(text.contains(LINK), "raw URL in the text body");
        assert!(
            html.contains("href=\"https://portal.example.com/acme/reset-password?token=a&amp;b=&quot;c&quot;\""),
            "{html}"
        );
    }

    #[test]
    fn a_blank_or_long_name_is_handled() {
        assert_eq!(display_name("  \n\t "), "your portal");
        assert_eq!(
            display_name(&"x".repeat(500)).chars().count(),
            MAX_NAME_CHARS
        );
        assert_eq!(display_name("Acme \n  Support"), "Acme Support");
    }
}

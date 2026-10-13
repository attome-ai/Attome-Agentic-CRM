//! Plain, inline templates (guidelines §0.5 — three similar functions beat a
//! templating engine for three emails). Each returns `(subject, text_body,
//! html_body)`.

/// BEM-14/F12 — the link is *data* placed inside an HTML attribute, so it is
/// escaped for that context. The text body keeps the raw URL: it is plain
/// text, and escaping it there would corrupt the address a mail client
/// linkifies.
fn href(target: &str) -> String {
    escape_html(target)
}

/// `reset_link` should already be the fully-qualified frontend URL
/// (`https://.../reset-password?token=...`) — this module has no notion of
/// `frontend_host`/`frontend_port`; the caller builds the link.
pub fn password_reset(reset_link: &str) -> (String, String, String) {
    let subject = "Reset your password".to_string();
    let text = format!(
        "We received a request to reset your password.\n\n\
         Reset it here (this link expires soon): {reset_link}\n\n\
         If you didn't request this, you can safely ignore this email — your \
         password will not be changed."
    );
    let html = format!(
        "<p>We received a request to reset your password.</p>\
         <p><a href=\"{}\">Reset your password</a> (this link expires soon)</p>\
         <p>If you didn't request this, you can safely ignore this email — your \
         password will not be changed.</p>",
        href(reset_link)
    );
    (subject, text, html)
}

/// `verify_link` should already be the fully-qualified frontend URL.
pub fn email_verification(verify_link: &str) -> (String, String, String) {
    let subject = "Verify your email address".to_string();
    let text = format!(
        "Please verify your email address to finish setting up your account.\n\n\
         Verify here: {verify_link}"
    );
    let html = format!(
        "<p>Please verify your email address to finish setting up your account.</p>\
         <p><a href=\"{}\">Verify your email</a></p>",
        href(verify_link)
    );
    (subject, text, html)
}

/// P-registration-gating Phase 2 (D-128) — `register_link` should already be
/// the fully-qualified frontend URL carrying the invitation token (e.g.
/// `.../register?invitation_token=...`).
pub fn invitation(register_link: &str) -> (String, String, String) {
    let subject = "You've been invited".to_string();
    let text = format!(
        "You've been invited to create an account.\n\n\
         Set up your account here (this link expires soon): {register_link}\n\n\
         If you weren't expecting this, you can safely ignore this email."
    );
    let html = format!(
        "<p>You've been invited to create an account.</p>\
         <p><a href=\"{}\">Set up your account</a> (this link expires soon)</p>\
         <p>If you weren't expecting this, you can safely ignore this email.</p>",
        href(register_link)
    );
    (subject, text, html)
}

/// Generic notification — plain body text wrapped in a single `<p>`. For
/// anything that doesn't need its own dedicated template.
pub fn generic_notification(subject: &str, body: &str) -> (String, String, String) {
    (
        subject.to_string(),
        body.to_string(),
        format!("<p>{}</p>", escape_html(body)),
    )
}

/// Minimal HTML entity escaping for interpolating untrusted text into a body
/// or an attribute. Owned by `attome-html`; re-exported here so callers with
/// their own templates (the web portal's, `xrm_portal::email`) keep their path.
pub use attome_html::escape_html;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_reset_carries_the_link_in_both_bodies() {
        let link = "https://app.example.com/reset-password?token=abc123";
        let (subject, text, html) = password_reset(link);
        assert_eq!(subject, "Reset your password");
        assert!(text.contains(link));
        assert!(html.contains(&format!("href=\"{link}\"")));
    }

    #[test]
    fn email_verification_carries_the_link_in_both_bodies() {
        let link = "https://app.example.com/verify?token=xyz789";
        let (subject, text, html) = email_verification(link);
        assert_eq!(subject, "Verify your email address");
        assert!(text.contains(link));
        assert!(html.contains(&format!("href=\"{link}\"")));
    }

    #[test]
    fn invitation_carries_the_link_in_both_bodies() {
        let link = "https://app.example.com/register?invitation_token=abc";
        let (subject, text, html) = invitation(link);
        assert_eq!(subject, "You've been invited");
        assert!(text.contains(link));
        assert!(html.contains(&format!("href=\"{link}\"")));
    }

    /// BEM-14 acceptance — a quote in the link must not break out of the
    /// href attribute and inject markup. The text body keeps the raw link.
    #[test]
    fn a_quote_in_the_link_is_escaped_inside_href() {
        let hostile = "https://app.example.com/x?token=a\" onmouseover=\"alert(1)";
        for (subject, _, html) in [
            password_reset(hostile),
            email_verification(hostile),
            invitation(hostile),
        ] {
            assert!(
                !html.contains("onmouseover=\"alert(1)\""),
                "{subject}: the attribute must not be breakable, got {html}"
            );
            assert!(
                html.contains("&quot;"),
                "{subject}: the quote must be entity-escaped, got {html}"
            );
        }
        let (_, text, _) = password_reset(hostile);
        assert!(
            text.contains(hostile),
            "the plain-text body must keep the link intact"
        );
    }

    #[test]
    fn generic_notification_wraps_the_body_in_a_single_paragraph() {
        let (subject, text, html) = generic_notification("Heads up", "Something happened.");
        assert_eq!(subject, "Heads up");
        assert_eq!(text, "Something happened.");
        assert_eq!(html, "<p>Something happened.</p>");
    }

    #[test]
    fn generic_notification_escapes_html_in_the_body() {
        let (_, text, html) =
            generic_notification("Heads up", "<script>alert(1)</script> & \"quoted\"");
        assert_eq!(text, "<script>alert(1)</script> & \"quoted\"");
        assert_eq!(
            html,
            "<p>&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quoted&quot;</p>"
        );
    }
}

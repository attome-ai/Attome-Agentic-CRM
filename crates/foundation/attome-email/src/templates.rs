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

/// B13-T10: the brand an email carries. The default is the plain email,
/// which names no product.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrandContext {
    /// The product name to show and sign with, such as "Acme CRM".
    pub app_name: Option<String>,
    /// An absolute URL of the published logo.
    pub logo_url: Option<String>,
    /// The brand colour for links, `#RRGGBB`; anything else is ignored.
    pub primary: Option<String>,
}

impl BrandContext {
    fn name(&self) -> Option<&str> {
        self.app_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
    }

    /// The HTML body with the logo (or the name) above it.
    fn frame(&self, inner: &str) -> String {
        let head = match (&self.logo_url, self.name()) {
            (Some(logo), name) => format!(
                "<p><img src=\"{}\" alt=\"{}\" height=\"40\"></p>",
                href(logo),
                escape_html(name.unwrap_or(""))
            ),
            (None, Some(name)) => format!("<p><strong>{}</strong></p>", escape_html(name)),
            (None, None) => String::new(),
        };
        format!("{head}{inner}")
    }

    /// A link in the brand colour.
    fn link(&self, target: &str, label: &str) -> String {
        let colour = self.primary.as_deref().filter(|c| {
            c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|d| d.is_ascii_hexdigit())
        });
        match colour {
            Some(c) => format!(
                "<a href=\"{}\" style=\"color:{c}\">{label}</a>",
                href(target)
            ),
            None => format!("<a href=\"{}\">{label}</a>", href(target)),
        }
    }

    /// The text body with the product name signed under it.
    fn sign(&self, text: String) -> String {
        match self.name() {
            Some(name) => format!("{text}\n\n{name}"),
            None => text,
        }
    }
}

/// `reset_link` should already be the fully-qualified frontend URL
/// (`https://.../reset-password?token=...`) — this module has no notion of
/// `frontend_host`/`frontend_port`; the caller builds the link.
pub fn password_reset(reset_link: &str, brand: &BrandContext) -> (String, String, String) {
    let subject = "Reset your password".to_string();
    let text = brand.sign(format!(
        "We received a request to reset your password.\n\n\
         Reset it here (this link expires soon): {reset_link}\n\n\
         If you didn't request this, you can safely ignore this email — your \
         password will not be changed."
    ));
    let html = brand.frame(&format!(
        "<p>We received a request to reset your password.</p>\
         <p>{} (this link expires soon)</p>\
         <p>If you didn't request this, you can safely ignore this email — your \
         password will not be changed.</p>",
        brand.link(reset_link, "Reset your password")
    ));
    (subject, text, html)
}

/// `verify_link` should already be the fully-qualified frontend URL.
pub fn email_verification(verify_link: &str, brand: &BrandContext) -> (String, String, String) {
    let subject = "Verify your email address".to_string();
    let text = brand.sign(format!(
        "Please verify your email address to finish setting up your account.\n\n\
         Verify here: {verify_link}"
    ));
    let html = brand.frame(&format!(
        "<p>Please verify your email address to finish setting up your account.</p>\
         <p>{}</p>",
        brand.link(verify_link, "Verify your email")
    ));
    (subject, text, html)
}

/// P-registration-gating Phase 2 (D-128) — `register_link` should already be
/// the fully-qualified frontend URL carrying the invitation token (e.g.
/// `.../register?invitation_token=...`).
pub fn invitation(register_link: &str, brand: &BrandContext) -> (String, String, String) {
    let subject = match brand.name() {
        Some(name) => format!("You've been invited to {name}"),
        None => "You've been invited".to_string(),
    };
    let text = brand.sign(format!(
        "You've been invited to create an account.\n\n\
         Set up your account here (this link expires soon): {register_link}\n\n\
         If you weren't expecting this, you can safely ignore this email."
    ));
    let html = brand.frame(&format!(
        "<p>You've been invited to create an account.</p>\
         <p>{} (this link expires soon)</p>\
         <p>If you weren't expecting this, you can safely ignore this email.</p>",
        brand.link(register_link, "Set up your account")
    ));
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
        let (subject, text, html) = password_reset(link, &BrandContext::default());
        assert_eq!(subject, "Reset your password");
        assert!(text.contains(link));
        assert!(html.contains(&format!("href=\"{link}\"")));
    }

    #[test]
    fn email_verification_carries_the_link_in_both_bodies() {
        let link = "https://app.example.com/verify?token=xyz789";
        let (subject, text, html) = email_verification(link, &BrandContext::default());
        assert_eq!(subject, "Verify your email address");
        assert!(text.contains(link));
        assert!(html.contains(&format!("href=\"{link}\"")));
    }

    #[test]
    fn invitation_carries_the_link_in_both_bodies() {
        let link = "https://app.example.com/register?invitation_token=abc";
        let (subject, text, html) = invitation(link, &BrandContext::default());
        assert_eq!(subject, "You've been invited");
        assert!(text.contains(link));
        assert!(html.contains(&format!("href=\"{link}\"")));
    }

    /// BEM-14 acceptance — a quote in the link must not break out of the
    /// href attribute and inject markup. The text body keeps the raw link.
    #[test]
    fn a_quote_in_the_link_is_escaped_inside_href() {
        let hostile = "https://app.example.com/x?token=a\" onmouseover=\"alert(1)";
        let plain = BrandContext::default();
        for (subject, _, html) in [
            password_reset(hostile, &plain),
            email_verification(hostile, &plain),
            invitation(hostile, &plain),
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
        let (_, text, _) = password_reset(hostile, &plain);
        assert!(
            text.contains(hostile),
            "the plain-text body must keep the link intact"
        );
    }

    #[test]
    fn reset_email_shows_the_brand() {
        let brand = BrandContext {
            app_name: Some("Acme <CRM>".into()),
            logo_url: Some("https://crm.acme.test/api/v1/branding/asset?kind=logo&v=abc".into()),
            primary: Some("#0b4f6c".into()),
        };
        let (_, text, html) = password_reset("https://crm.acme.test/reset", &brand);
        assert!(html.starts_with(
            "<p><img src=\"https://crm.acme.test/api/v1/branding/asset?kind=logo&amp;v=abc\""
        ));
        assert!(html.contains("alt=\"Acme &lt;CRM&gt;\""));
        assert!(html.contains("style=\"color:#0b4f6c\""));
        assert!(text.ends_with("\n\nAcme <CRM>"));
    }

    #[test]
    fn reset_email_hides_vendor_name() {
        for brand in [
            BrandContext::default(),
            BrandContext {
                app_name: Some("Acme".into()),
                ..BrandContext::default()
            },
        ] {
            let (subject, text, html) = password_reset("https://x.test/r", &brand);
            for part in [&subject, &text, &html] {
                assert!(!part.contains("Attome"), "{part}");
            }
        }
    }

    #[test]
    fn a_bad_brand_colour_is_ignored() {
        let brand = BrandContext {
            primary: Some("red;background:url(x)".into()),
            ..BrandContext::default()
        };
        let (_, _, html) = invitation("https://x.test/i", &brand);
        assert!(!html.contains("style="));
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

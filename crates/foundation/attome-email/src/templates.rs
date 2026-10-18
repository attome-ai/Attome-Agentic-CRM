//! The platform's own emails (roadmap Z8-T7), written in the one template
//! language (`attome_html::tmpl`, Z13): each has an English and an Arabic
//! version, the Arabic laid out right to left, and an HTML and a plain-text
//! part. Each function returns `(subject, text_body, html_body)`.
//!
//! Every value is escaped for where it lands (Z13-T3): a link in `href` is a
//! URL (only http, https, mailto and tel pass, the rest percent-encoded), a
//! name is text. The plain-text part keeps the raw link: escaping it there
//! would corrupt the address a mail client linkifies.
//!
//! The functions without a language are English; the `_in` forms take one
//! (`ar` for Arabic; anything else is English).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use attome_html::tmpl::{Output, OutputKey, RenderContext, TemplateSet};
use attome_rules::{Context, Schema, Type, Value};

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

    fn colour(&self) -> Option<&str> {
        self.primary.as_deref().filter(|c| {
            c.len() == 7 && c.starts_with('#') && c[1..].chars().all(|d| d.is_ascii_hexdigit())
        })
    }
}

/// The logo, or the product name, above the message, in the language's
/// direction.
const FRAME: &str = "<div dir=\"{{ dir }}\">{% if has_logo %}<p><img src=\"{{ logo }}\" alt=\"{{ name }}\" height=\"40\"></p>{% else %}{% if has_name %}<p><strong>{{ name }}</strong></p>{% end %}{% end %}{% body %}</div>";

/// The product name signed under a plain-text part.
const SIGN: &str = "{% if has_name %}\n\n{{ name }}{% end %}";

/// The link, in the brand colour when there is one.
const OPEN_LINK: &str =
    "<a href=\"{{ link }}\"{% if has_colour %} style=\"color:{{ colour }}\"{% end %}>";

/// One email's subject and body templates.
struct Email {
    subject: TemplateSet,
    body: TemplateSet,
}

fn set(variants: Vec<(&str, OutputKey, String)>) -> TemplateSet {
    TemplateSet {
        default_language: "en".to_owned(),
        variants: variants
            .into_iter()
            .map(|(lang, output, source)| ((lang.to_owned(), output), source))
            .collect(),
        layouts: [("frame".to_owned(), FRAME.to_owned())]
            .into_iter()
            .collect(),
        partials: [
            ("sign".to_owned(), SIGN.to_owned()),
            ("open_link".to_owned(), OPEN_LINK.to_owned()),
        ]
        .into_iter()
        .collect::<BTreeMap<_, _>>(),
    }
}

/// An email from its subjects and its English and Arabic text and HTML.
fn email(subject_en: &str, subject_ar: &str, en: [&str; 2], ar: [&str; 2]) -> Email {
    Email {
        subject: set(vec![
            ("en", OutputKey::Text, subject_en.to_owned()),
            ("ar", OutputKey::Text, subject_ar.to_owned()),
        ]),
        body: set(vec![
            (
                "en",
                OutputKey::Text,
                format!("{}{{% include 'sign' %}}", en[0]),
            ),
            (
                "en",
                OutputKey::Html,
                format!("{{% layout 'frame' %}}{}", en[1]),
            ),
            (
                "ar",
                OutputKey::Text,
                format!("{}{{% include 'sign' %}}", ar[0]),
            ),
            (
                "ar",
                OutputKey::Html,
                format!("{{% layout 'frame' %}}{}", ar[1]),
            ),
        ]),
    }
}

static RESET: LazyLock<Email> = LazyLock::new(|| {
    email(
        "Reset your password",
        "إعادة تعيين كلمة المرور",
        [
            "We received a request to reset your password.\n\nReset it here (this link expires soon): {{ link }}\n\nIf you didn't request this, you can safely ignore this email — your password will not be changed.",
            "<p>We received a request to reset your password.</p><p>{% include 'open_link' %}Reset your password</a> (this link expires soon)</p><p>If you didn't request this, you can safely ignore this email — your password will not be changed.</p>",
        ],
        [
            "تلقينا طلبًا لإعادة تعيين كلمة المرور الخاصة بك.\n\nأعد تعيينها من هنا (تنتهي صلاحية هذا الرابط قريبًا): {{ link }}\n\nإن لم تطلب ذلك، يمكنك تجاهل هذه الرسالة بأمان، ولن تتغير كلمة المرور.",
            "<p>تلقينا طلبًا لإعادة تعيين كلمة المرور الخاصة بك.</p><p>{% include 'open_link' %}إعادة تعيين كلمة المرور</a> (تنتهي صلاحية هذا الرابط قريبًا)</p><p>إن لم تطلب ذلك، يمكنك تجاهل هذه الرسالة بأمان، ولن تتغير كلمة المرور.</p>",
        ],
    )
});

static VERIFY: LazyLock<Email> = LazyLock::new(|| {
    email(
        "Verify your email address",
        "تأكيد عنوان بريدك الإلكتروني",
        [
            "Please verify your email address to finish setting up your account.\n\nVerify here: {{ link }}",
            "<p>Please verify your email address to finish setting up your account.</p><p>{% include 'open_link' %}Verify your email</a></p>",
        ],
        [
            "يرجى تأكيد عنوان بريدك الإلكتروني لإكمال إعداد حسابك.\n\nأكّده من هنا: {{ link }}",
            "<p>يرجى تأكيد عنوان بريدك الإلكتروني لإكمال إعداد حسابك.</p><p>{% include 'open_link' %}تأكيد البريد الإلكتروني</a></p>",
        ],
    )
});

static INVITATION: LazyLock<Email> = LazyLock::new(|| {
    email(
        "{% if has_name %}You've been invited to {{ name }}{% else %}You've been invited{% end %}",
        "{% if has_name %}تمت دعوتك إلى {{ name }}{% else %}تمت دعوتك{% end %}",
        [
            "You've been invited to create an account.\n\nSet up your account here (this link expires soon): {{ link }}\n\nIf you weren't expecting this, you can safely ignore this email.",
            "<p>You've been invited to create an account.</p><p>{% include 'open_link' %}Set up your account</a> (this link expires soon)</p><p>If you weren't expecting this, you can safely ignore this email.</p>",
        ],
        [
            "تمت دعوتك لإنشاء حساب.\n\nأعدّ حسابك من هنا (تنتهي صلاحية هذا الرابط قريبًا): {{ link }}\n\nإن لم تكن تتوقع هذه الدعوة، يمكنك تجاهل هذه الرسالة بأمان.",
            "<p>تمت دعوتك لإنشاء حساب.</p><p>{% include 'open_link' %}إعداد حسابك</a> (تنتهي صلاحية هذا الرابط قريبًا)</p><p>إن لم تكن تتوقع هذه الدعوة، يمكنك تجاهل هذه الرسالة بأمان.</p>",
        ],
    )
});

static GENERIC: LazyLock<TemplateSet> = LazyLock::new(|| {
    set(vec![
        ("en", OutputKey::Text, "{{ body }}".to_owned()),
        ("en", OutputKey::Html, "<p>{{ body }}</p>".to_owned()),
        ("ar", OutputKey::Text, "{{ body }}".to_owned()),
        (
            "ar",
            OutputKey::Html,
            "<p dir=\"rtl\">{{ body }}</p>".to_owned(),
        ),
    ])
});

fn language(lang: &str) -> &'static str {
    if lang.trim().to_ascii_lowercase().starts_with("ar") {
        "ar"
    } else {
        "en"
    }
}

const FIELDS: [&str; 9] = [
    "dir",
    "link",
    "name",
    "logo",
    "colour",
    "body",
    "has_name",
    "has_logo",
    "has_colour",
];

fn schema() -> Schema {
    FIELDS.iter().fold(Schema::new(), |schema, field| {
        let ty = if field.starts_with("has_") {
            Type::Bool
        } else {
            Type::Text
        };
        schema.with_field(*field, ty)
    })
}

fn values(lang: &str, link: &str, brand: &BrandContext, body: &str) -> Context {
    let text = |s: &str| Value::Text(s.to_owned());
    Context::new(chrono::Utc::now())
        .with_field("dir", text(if lang == "ar" { "rtl" } else { "ltr" }))
        .with_field("link", text(link))
        .with_field("name", text(brand.name().unwrap_or("")))
        .with_field("logo", text(brand.logo_url.as_deref().unwrap_or("")))
        .with_field("colour", text(brand.colour().unwrap_or("")))
        .with_field("body", text(body))
        .with_field("has_name", Value::Bool(brand.name().is_some()))
        .with_field("has_logo", Value::Bool(brand.logo_url.is_some()))
        .with_field("has_colour", Value::Bool(brand.colour().is_some()))
}

/// Renders `set`'s variant, or (a bug in a built-in template, which the
/// tests rule out) logs it and answers `fallback`.
fn render(
    set: &TemplateSet,
    lang: &str,
    output: Output,
    values: &Context,
    fallback: &str,
) -> String {
    let ctx = RenderContext::new(values.clone(), lang, output);
    match set.render(lang, &schema(), &ctx) {
        Ok(rendered) => rendered.text,
        Err(error) => {
            tracing::error!(%error, "email template failed to render; sending the plain fallback");
            fallback.to_owned()
        }
    }
}

fn compose(
    email: &Email,
    lang: &str,
    link: &str,
    brand: &BrandContext,
) -> (String, String, String) {
    let lang = language(lang);
    let values = values(lang, link, brand, "");
    (
        render(&email.subject, lang, Output::Text, &values, ""),
        render(&email.body, lang, Output::Text, &values, link),
        render(
            &email.body,
            lang,
            Output::Html,
            &values,
            &format!("<p>{}</p>", escape_html(link)),
        ),
    )
}

/// `reset_link` should already be the fully-qualified frontend URL
/// (`https://.../reset-password?token=...`) — this module has no notion of
/// `frontend_host`/`frontend_port`; the caller builds the link.
pub fn password_reset(reset_link: &str, brand: &BrandContext) -> (String, String, String) {
    password_reset_in("en", reset_link, brand)
}

/// [`password_reset`] in `lang`.
pub fn password_reset_in(
    lang: &str,
    reset_link: &str,
    brand: &BrandContext,
) -> (String, String, String) {
    compose(&RESET, lang, reset_link, brand)
}

/// `verify_link` should already be the fully-qualified frontend URL.
pub fn email_verification(verify_link: &str, brand: &BrandContext) -> (String, String, String) {
    email_verification_in("en", verify_link, brand)
}

/// [`email_verification`] in `lang`.
pub fn email_verification_in(
    lang: &str,
    verify_link: &str,
    brand: &BrandContext,
) -> (String, String, String) {
    compose(&VERIFY, lang, verify_link, brand)
}

/// P-registration-gating Phase 2 (D-128) — `register_link` should already be
/// the fully-qualified frontend URL carrying the invitation token (e.g.
/// `.../register?invitation_token=...`).
pub fn invitation(register_link: &str, brand: &BrandContext) -> (String, String, String) {
    invitation_in("en", register_link, brand)
}

/// [`invitation`] in `lang`.
pub fn invitation_in(
    lang: &str,
    register_link: &str,
    brand: &BrandContext,
) -> (String, String, String) {
    compose(&INVITATION, lang, register_link, brand)
}

/// Generic notification — plain body text wrapped in a single `<p>`. For
/// anything that doesn't need its own dedicated template.
pub fn generic_notification(subject: &str, body: &str) -> (String, String, String) {
    generic_notification_in("en", subject, body)
}

/// [`generic_notification`] in `lang` (the Arabic paragraph is right to left).
pub fn generic_notification_in(lang: &str, subject: &str, body: &str) -> (String, String, String) {
    let lang = language(lang);
    let values = values(lang, "", &BrandContext::default(), body);
    (
        subject.to_string(),
        render(&GENERIC, lang, Output::Text, &values, body),
        render(
            &GENERIC,
            lang,
            Output::Html,
            &values,
            &format!("<p>{}</p>", escape_html(body)),
        ),
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
    fn templates_all_render_in_both_languages() {
        let brand = BrandContext {
            app_name: Some("Acme".into()),
            logo_url: Some("https://crm.acme.test/logo.png".into()),
            primary: Some("#0b4f6c".into()),
        };
        for email in [&*RESET, &*VERIFY, &*INVITATION] {
            for lang in ["en", "ar"] {
                let values = values(lang, "https://x.test/l", &brand, "");
                for (set, output) in [
                    (&email.subject, Output::Text),
                    (&email.body, Output::Text),
                    (&email.body, Output::Html),
                ] {
                    let ctx = RenderContext::new(values.clone(), lang, output);
                    let rendered = set.render(lang, &schema(), &ctx);
                    assert!(rendered.is_ok(), "{lang} {output:?}: {rendered:?}");
                }
            }
        }
    }

    #[test]
    fn templates_snapshot_the_english_reset() {
        let (subject, text, html) = password_reset(
            "https://app.example.com/reset?token=abc",
            &BrandContext::default(),
        );
        assert_eq!(subject, "Reset your password");
        assert_eq!(
            text,
            "We received a request to reset your password.\n\nReset it here (this link expires \
             soon): https://app.example.com/reset?token=abc\n\nIf you didn't request this, you can \
             safely ignore this email — your password will not be changed."
        );
        assert_eq!(
            html,
            "<div dir=\"ltr\"><p>We received a request to reset your password.</p><p><a \
             href=\"https://app.example.com/reset?token=abc\">Reset your password</a> (this link \
             expires soon)</p><p>If you didn't request this, you can safely ignore this email — \
             your password will not be changed.</p></div>"
        );
    }

    #[test]
    fn templates_snapshot_the_arabic_reset() {
        let brand = BrandContext {
            app_name: Some("أتوم".into()),
            ..BrandContext::default()
        };
        let (subject, text, html) =
            password_reset_in("ar-SA", "https://app.example.com/reset?token=abc", &brand);
        assert_eq!(subject, "إعادة تعيين كلمة المرور");
        assert!(text.ends_with("\n\nأتوم"), "{text}");
        assert_eq!(
            html,
            "<div dir=\"rtl\"><p><strong>أتوم</strong></p><p>تلقينا طلبًا لإعادة تعيين كلمة المرور \
             الخاصة بك.</p><p><a href=\"https://app.example.com/reset?token=abc\">إعادة تعيين \
             كلمة المرور</a> (تنتهي صلاحية هذا الرابط قريبًا)</p><p>إن لم تطلب ذلك، يمكنك تجاهل \
             هذه الرسالة بأمان، ولن تتغير كلمة المرور.</p></div>"
        );
        let (subject, _, _) = invitation_in("ar", "https://x.test/i", &brand);
        assert_eq!(subject, "تمت دعوتك إلى أتوم");
    }

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
                html.contains("%22"),
                "{subject}: the quote must be percent-encoded in the URL, got {html}"
            );
        }
        let (_, text, _) = password_reset(hostile, &plain);
        assert!(
            text.contains(hostile),
            "the plain-text body must keep the link intact"
        );
        let (_, _, html) = password_reset("javascript:alert(1)", &plain);
        assert!(html.contains("href=\"#\""), "{html}");
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
            "<div dir=\"ltr\"><p><img src=\"https://crm.acme.test/api/v1/branding/asset?kind=logo&amp;v=abc\""
        ), "{html}");
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
        let (_, _, ar) = generic_notification_in("ar", "تنبيه", "حدث شيء.");
        assert_eq!(ar, "<p dir=\"rtl\">حدث شيء.</p>");
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

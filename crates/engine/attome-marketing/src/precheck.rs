//! The pre-send check (roadmap E6-T10): a score from 0 to 100 and the
//! findings behind it for one rendered email and its audience. It decides
//! nothing: E3's send reads the score. No model is involved.
//!
//! Findings: spam wording (the phrase lists in `data/`, Arabic text
//! normalised first), image-heavy content, links to blocklisted domains, no
//! unsubscribe link, no plain-text part, a message over 100 KB, an audience
//! mostly never mailed before, and more than 5% invalid addresses. Each
//! carries a stable code, a severity and a guidance key the screens
//! translate (`deliverabilityGuidance.<code>`); no English text comes back.

use std::collections::HashSet;

use serde::Serialize;
use utoipa::ToSchema;

/// The score a message needs to pass.
pub const PASS_MARK: u8 = 70;
/// The largest message that draws no finding.
pub const MAX_BYTES: usize = 100 * 1024;
/// Image share above which a message is image-heavy.
pub const MAX_IMAGE_SHARE: f64 = 0.6;
/// Text an image counts as, for the image share.
const IMAGE_WEIGHT: usize = 500;
/// Invalid share above which the audience is flagged.
pub const MAX_INVALID_SHARE: f64 = 0.05;

const SPAM_EN: &str = include_str!("../data/spam_words_en.txt");
const SPAM_AR: &str = include_str!("../data/spam_words_ar.txt");

/// How much a finding costs the score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = PrecheckSeverity)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    fn cost(self) -> u8 {
        match self {
            Self::Error => 40,
            Self::Warning => 15,
            Self::Info => 5,
        }
    }
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
#[schema(as = PrecheckFinding)]
pub struct Finding {
    pub code: &'static str,
    pub severity: Severity,
    /// The screens' translation key for what to do about it.
    pub guidance_key: String,
    /// What matched (a phrase, a domain), when there is one.
    pub detail: Option<String>,
}

/// The check's answer.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct PrecheckReport {
    pub score: u8,
    pub passed: bool,
    pub findings: Vec<Finding>,
}

/// The message as rendered for sending.
#[derive(Debug, Clone, Copy)]
pub struct PrecheckEmail<'a> {
    pub html: &'a str,
    pub text: Option<&'a str>,
    pub size_bytes: usize,
}

/// The audience, counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AudienceStats {
    pub recipients: i64,
    pub never_mailed: i64,
    pub invalid: i64,
}

/// Arabic and Latin text in one comparable form: lower case; alef forms to
/// alef, ta marbuta to ha, alef maqsura to ya; diacritics and tatweel gone;
/// runs of white space as one space. Pure.
pub fn normalise(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        let c = match c {
            '\u{064B}'..='\u{065F}' | '\u{0670}' | '\u{0640}' => continue,
            'أ' | 'إ' | 'آ' | 'ٱ' => 'ا',
            'ة' => 'ه',
            'ى' => 'ي',
            c => c,
        };
        if c.is_whitespace() {
            if !space && !out.is_empty() {
                out.push(' ');
            }
            space = true;
        } else {
            out.extend(c.to_lowercase());
            space = false;
        }
    }
    out.trim_end().to_owned()
}

fn phrases() -> Vec<String> {
    SPAM_EN
        .lines()
        .chain(SPAM_AR.lines())
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(normalise)
        .collect()
}

/// The visible text of an HTML body: tags dropped. Pure.
fn visible_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// The host of every `href` in the body, lower case. Pure.
fn link_domains(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut rest = lower.as_str();
    while let Some(i) = rest.find("href=") {
        rest = &rest[i + 5..];
        let value = rest.trim_start_matches(['"', '\'']);
        let end = value.find(['"', '\'', ' ', '>']).unwrap_or(value.len());
        let url = &value[..end];
        if let Some((_, after)) = url.split_once("://") {
            let host = after.split(['/', '?', '#', ':']).next().unwrap_or("");
            if !host.is_empty() {
                out.push(host.trim_start_matches("www.").to_owned());
            }
        }
    }
    out
}

fn finding(code: &'static str, severity: Severity, detail: Option<String>) -> Finding {
    Finding {
        code,
        severity,
        guidance_key: format!("deliverabilityGuidance.{code}"),
        detail,
    }
}

/// Checks one message and audience. Pure.
pub fn precheck(
    email: PrecheckEmail<'_>,
    audience: AudienceStats,
    blocklisted_domains: &HashSet<String>,
) -> PrecheckReport {
    let mut findings = Vec::new();
    let visible = visible_text(email.html);
    let combined = normalise(&format!("{visible} {}", email.text.unwrap_or_default()));
    let padded = format!(" {combined} ");

    if let Some(phrase) = phrases()
        .into_iter()
        .find(|p| padded.contains(&format!(" {p} ")) || padded.contains(&format!(" {p}")))
    {
        findings.push(finding("spam_wording", Severity::Warning, Some(phrase)));
    }

    let images = email.html.to_ascii_lowercase().matches("<img").count();
    let text_chars = visible.split_whitespace().map(str::len).sum::<usize>();
    let image_chars = images * IMAGE_WEIGHT;
    if image_chars > 0 && image_chars as f64 / (image_chars + text_chars) as f64 > MAX_IMAGE_SHARE {
        findings.push(finding("image_heavy", Severity::Warning, None));
    }

    if let Some(domain) = link_domains(email.html)
        .into_iter()
        .find(|d| blocklisted_domains.contains(d))
    {
        findings.push(finding("blocklisted_link", Severity::Error, Some(domain)));
    }

    let lower = email.html.to_ascii_lowercase();
    let has_unsubscribe = lower.contains("unsubscribe")
        || lower.contains("{{unsubscribe")
        || combined.contains(&normalise("إلغاء الاشتراك"));
    if !has_unsubscribe {
        findings.push(finding("missing_unsubscribe", Severity::Error, None));
    }

    if email.text.is_none_or(|t| t.trim().is_empty()) {
        findings.push(finding("missing_text_part", Severity::Warning, None));
    }

    if email.size_bytes > MAX_BYTES {
        findings.push(finding(
            "too_large",
            Severity::Warning,
            Some(format!("{} KB", email.size_bytes / 1024)),
        ));
    }

    if audience.recipients > 0 {
        let never = audience.never_mailed as f64 / audience.recipients as f64;
        if never > 0.5 {
            findings.push(finding("never_mailed_audience", Severity::Info, None));
        }
        let invalid = audience.invalid as f64 / audience.recipients as f64;
        if invalid > MAX_INVALID_SHARE {
            findings.push(finding(
                "invalid_share",
                Severity::Error,
                Some(format!("{:.1}%", invalid * 100.0)),
            ));
        }
    }

    let cost: u32 = findings.iter().map(|f| u32::from(f.severity.cost())).sum();
    let score = 100u32.saturating_sub(cost) as u8;
    PrecheckReport {
        score,
        passed: score >= PASS_MARK,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "<p>Our autumn catalogue is out.</p><a href=\"https://shop.example.com/a\">See it</a> \
                        <a href=\"{{unsubscribe_url}}\">Unsubscribe</a>";

    fn email(html: &str) -> PrecheckEmail<'_> {
        PrecheckEmail {
            html,
            text: Some("Our autumn catalogue is out."),
            size_bytes: html.len(),
        }
    }

    fn codes(r: &PrecheckReport) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn missing_unsubscribe_fails() {
        let report = precheck(
            email("<p>Our autumn catalogue is out.</p>"),
            AudienceStats::default(),
            &HashSet::new(),
        );
        assert!(codes(&report).contains(&"missing_unsubscribe"));
        assert!(!report.passed, "score {}", report.score);
        let good = precheck(email(GOOD), AudienceStats::default(), &HashSet::new());
        assert!(good.passed, "{:?}", good.findings);
        assert!(good.findings.is_empty(), "{:?}", good.findings);
    }

    #[test]
    fn arabic_spam_phrase_found_after_normalising() {
        assert_eq!(normalise("عَرْضٌ مَحْدُوْد"), "عرض محدود");
        assert_eq!(normalise("إلغاء  الاشتراك"), "الغاء الاشتراك");
        assert_eq!(normalise("هدية مجانيـــة"), "هديه مجانيه");
        // The shipped Arabic list is empty until approved; the English list
        // matches through the same normalisation.
        let report = precheck(
            email(&format!("{GOOD}<p>ACT   NOW and claim it</p>")),
            AudienceStats::default(),
            &HashSet::new(),
        );
        assert_eq!(report.findings[0].code, "spam_wording");
        assert_eq!(report.findings[0].detail.as_deref(), Some("act now"));
    }

    #[test]
    fn image_heavy_message_flagged() {
        let html = format!("{GOOD}<img src=\"a.png\"><img src=\"b.png\"><img src=\"c.png\">");
        let report = precheck(email(&html), AudienceStats::default(), &HashSet::new());
        assert!(codes(&report).contains(&"image_heavy"));
        let blocked = HashSet::from(["shop.example.com".to_owned()]);
        let report = precheck(email(GOOD), AudienceStats::default(), &blocked);
        assert!(codes(&report).contains(&"blocklisted_link"));
        let audience = AudienceStats {
            recipients: 100,
            never_mailed: 80,
            invalid: 6,
        };
        let report = precheck(email(GOOD), audience, &HashSet::new());
        assert_eq!(
            codes(&report),
            vec!["never_mailed_audience", "invalid_share"]
        );
    }
}

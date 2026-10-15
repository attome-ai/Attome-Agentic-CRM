//! The platform's one HTML allow-list sanitizer (D-605, basic-units B-R7).
//!
//! **Why this crate exists.** A `rich_text` field (field type 17) stores HTML
//! a user typed into a browser editor. Stored HTML is rendered later by other
//! people's browsers, so it is sanitized **on write, server-side, with an
//! allow-list**: whatever reaches the database is already safe, whatever the
//! client did. The email plan's EM2 (inbound HTML mail) needs the same
//! primitive, so it lives here, in a base crate both the entity engine and a
//! mail pipeline can reach, rather than inside either of them.
//!
//! **What it is built on.** `ammonia`, a pure-Rust allow-list sanitizer over
//! `html5ever` — the same HTML parser `scraper` (xrm-webcrawl) already puts in
//! the dependency tree. A real HTML5 parser, not a regex: sanitizing with a
//! regex is how every "strip `<script>`" filter in history was bypassed.
//!
//! **No I/O, no xrm-* knowledge.** Pure functions of a `&str`.
//!
//! The allow-list ([`RICH_TEXT_TAGS`], [`RICH_TEXT_URL_SCHEMES`]) is basic
//! formatting only: paragraphs, line breaks, bold/italic/underline/strike,
//! headings, lists, quotes, code, and links. Everything else is removed:
//! `<script>`/`<style>`/`<noscript>` together with their content, `<iframe>`, `<object>`,
//! `<embed>`, `<img>`, forms, every `on*` event-handler attribute, every
//! `style`/`class`/`id` attribute, comments, and any link whose URL is not
//! `http:`, `https:`, `mailto:` or `tel:` (so `javascript:`, `vbscript:` and
//! `data:` never survive). Relative URLs are dropped too: a stored record is
//! rendered on pages whose base URL the author does not control.
//!
//! [`escape_html`] and [`merge_placeholders`] (the `template` module) are the
//! output-side twins: escaping a value into HTML and the one `{{name}}`
//! substitution every template-rendering crate uses.

use std::collections::{HashMap, HashSet};

mod template;
pub use template::{escape_html, merge_placeholders};

use ammonia::{Builder, UrlRelative};

/// Elements a rich-text value may contain. Anything not listed is removed
/// (its text content is kept, except for [`REMOVED_WITH_CONTENT`]).
pub const RICH_TEXT_TAGS: &[&str] = &[
    "a",
    "b",
    "blockquote",
    "br",
    "code",
    "div",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "span",
    "strong",
    "sub",
    "sup",
    "u",
    "ul",
];

/// URL schemes an `<a href>` may use. `data:`, `javascript:` and every other
/// scheme are removed with the attribute.
pub const RICH_TEXT_URL_SCHEMES: &[&str] = &["http", "https", "mailto", "tel"];

/// Elements removed together with everything inside them — their content is
/// code, presentation, or a scripting-disabled fallback, never prose.
/// `noscript` joined the list with owner decision 4 (CLEANUP-REVIEW batch 1),
/// so a crawled page's "please enable JavaScript" fallback never reaches the
/// text `html_to_text` extracts.
pub const REMOVED_WITH_CONTENT: &[&str] = &["script", "style", "noscript"];

/// The `rel` every surviving link carries, so a link can neither reach back
/// into the page that opened it nor leak it as a referrer.
const LINK_REL: &str = "noopener noreferrer nofollow";

fn text_only_builder() -> Builder<'static> {
    let mut builder = Builder::empty();
    builder
        .clean_content_tags(REMOVED_WITH_CONTENT.iter().copied().collect())
        .strip_comments(true);
    builder
}

/// Sanitizes a rich-text value against the allow-list above. The result is
/// safe to store and to render as HTML. Idempotent: sanitizing an already
/// sanitized value returns it unchanged.
pub fn sanitize_rich_text(input: &str) -> String {
    sanitize(input, SanitizeProfile::RichText)
}

/// Z13-T1: which allow-list a piece of HTML is cleaned against. Every
/// profile removes scripts, styles and `noscript` with their content,
/// every event-handler attribute, comments, and any URL that is not
/// `http:`, `https:`, `mailto:` or `tel:` (relative URLs too).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SanitizeProfile {
    /// A rich-text field: basic formatting and links ([`RICH_TEXT_TAGS`]).
    RichText,
    /// An email received from outside: rich text plus tables, and images
    /// only when the reader chose to load remote images (a remote image is a
    /// read receipt for the sender).
    InboundEmail { allow_remote_images: bool },
    /// A portal page an administrator wrote: rich text plus all headings,
    /// tables, figures and images.
    PortalPage,
    /// Text inside a custom component: a fixed handful of text-level tags,
    /// no links, no attributes.
    CustomComponent,
}

/// Table elements the email and portal profiles add.
const TABLE_TAGS: &[&str] = &[
    "caption", "col", "colgroup", "table", "tbody", "td", "tfoot", "th", "thead", "tr",
];

/// The only elements a custom component's text may hold.
const COMPONENT_TAGS: &[&str] = &[
    "b", "br", "em", "i", "li", "ol", "p", "span", "strong", "u", "ul",
];

fn profile_builder(profile: SanitizeProfile) -> Builder<'static> {
    let mut tags: HashSet<&'static str> = RICH_TEXT_TAGS.iter().copied().collect();
    let mut tag_attributes: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    tag_attributes.insert("a", ["href", "title"].into_iter().collect());
    let images = |tags: &mut HashSet<&'static str>,
                  attrs: &mut HashMap<&'static str, HashSet<&'static str>>| {
        tags.insert("img");
        attrs.insert(
            "img",
            ["src", "alt", "width", "height"].into_iter().collect(),
        );
    };
    match profile {
        SanitizeProfile::RichText => {}
        SanitizeProfile::InboundEmail {
            allow_remote_images,
        } => {
            tags.extend(TABLE_TAGS.iter().copied());
            for cell in ["td", "th"] {
                tag_attributes.insert(cell, ["colspan", "rowspan"].into_iter().collect());
            }
            if allow_remote_images {
                images(&mut tags, &mut tag_attributes);
            }
        }
        SanitizeProfile::PortalPage => {
            tags.extend(TABLE_TAGS.iter().copied());
            tags.extend(["h5", "h6", "figure", "figcaption"]);
            for cell in ["td", "th"] {
                tag_attributes.insert(cell, ["colspan", "rowspan"].into_iter().collect());
            }
            images(&mut tags, &mut tag_attributes);
        }
        SanitizeProfile::CustomComponent => {
            tags = COMPONENT_TAGS.iter().copied().collect();
            tag_attributes.clear();
        }
    }
    let mut builder = Builder::empty();
    builder
        .tags(tags)
        .clean_content_tags(REMOVED_WITH_CONTENT.iter().copied().collect())
        .tag_attributes(tag_attributes)
        .url_schemes(RICH_TEXT_URL_SCHEMES.iter().copied().collect())
        .url_relative(UrlRelative::Deny)
        .link_rel(Some(LINK_REL))
        .strip_comments(true);
    builder
}

/// Z13-T1: cleans `input` against `profile`'s allow-list. The result is safe
/// to store and to render as HTML.
pub fn sanitize(input: &str, profile: SanitizeProfile) -> String {
    profile_builder(profile).clean(input).to_string()
}

/// The visible text of an HTML fragment: every tag removed, `<script>`/
/// `<style>`/`<noscript>` content dropped, entities decoded, whitespace collapsed. Used
/// where a rich-text value has to be *read* rather than rendered — the search
/// corpus, list cells, notifications, crawled web pages (xrm-webcrawl).
pub fn html_to_text(input: &str) -> String {
    // Tags are removed, not replaced, so adjacent blocks would run together
    // ("<p>a</p><p>b</p>" -> "ab"). A space before every tag keeps words
    // apart; the whitespace collapse below removes the surplus.
    let spaced = input.replace('<', " <");
    let stripped = text_only_builder().clean(&spaced).to_string();
    let decoded = decode_entities(&stripped);
    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Decodes the entities the serializer emits for text content (`&amp;`,
/// `&lt;`, `&gt;`, `&quot;`, `&nbsp;`, numeric references). Anything else is
/// left as written.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail[..tail.len().min(12)].find(';') else {
            out.push('&');
            rest = &tail[1..];
            continue;
        };
        let entity = &tail[1..semi];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &tail[semi + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_basic_formatting() {
        let html = "<p>Hello <strong>bold</strong> <em>it</em> <u>u</u></p><ul><li>one</li></ul>";
        assert_eq!(sanitize_rich_text(html), html);
    }

    #[test]
    fn removes_script_and_its_content() {
        let out = sanitize_rich_text("<p>ok</p><script>alert(1)</script>");
        assert_eq!(out, "<p>ok</p>");
    }

    #[test]
    fn removes_style_and_its_content() {
        let out = sanitize_rich_text("<style>p{color:red}</style><p>x</p>");
        assert_eq!(out, "<p>x</p>");
    }

    #[test]
    fn removes_event_handlers_and_style_attributes() {
        let out =
            sanitize_rich_text(r#"<p onclick="alert(1)" style="color:red" class="c" id="i">x</p>"#);
        assert_eq!(out, "<p>x</p>");
    }

    #[test]
    fn removes_iframes_objects_embeds_and_images() {
        let out = sanitize_rich_text(
            r#"<iframe src="https://evil.example"></iframe><object data="x"></object><embed src="y"><img src="z" onerror="alert(1)"><p>t</p>"#,
        );
        assert!(!out.contains("iframe"), "{out}");
        assert!(!out.contains("object"), "{out}");
        assert!(!out.contains("embed"), "{out}");
        assert!(!out.contains("img"), "{out}");
        assert!(!out.contains("onerror"), "{out}");
        assert!(out.contains("<p>t</p>"), "{out}");
    }

    #[test]
    fn keeps_safe_links_and_adds_rel() {
        let out = sanitize_rich_text(r#"<a href="https://example.com" target="_blank">x</a>"#);
        assert_eq!(
            out,
            r#"<a href="https://example.com" rel="noopener noreferrer nofollow">x</a>"#
        );
        let mail = sanitize_rich_text(r#"<a href="mailto:a@example.com">m</a>"#);
        assert!(mail.contains(r#"href="mailto:a@example.com""#), "{mail}");
    }

    #[test]
    fn drops_javascript_data_and_relative_urls() {
        for href in [
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            " javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
            "/relative/path",
        ] {
            let out = sanitize_rich_text(&format!(r#"<a href="{href}">x</a>"#));
            assert!(!out.contains("href"), "{href} survived: {out}");
        }
    }

    #[test]
    fn removes_comments_and_svg() {
        let out = sanitize_rich_text("<!-- c --><svg onload=alert(1)><circle/></svg><p>x</p>");
        assert_eq!(out, "<p>x</p>");
    }

    #[test]
    fn is_idempotent() {
        let once = sanitize_rich_text(
            r#"<p>a &amp; b <a href="https://x.example">l</a><script>bad()</script></p>"#,
        );
        assert_eq!(sanitize_rich_text(&once), once);
    }

    #[test]
    fn html_to_text_strips_tags_and_decodes() {
        assert_eq!(
            html_to_text(
                "<p>Fish &amp; <b>chips</b></p><p>second&nbsp;para</p><script>x()</script>"
            ),
            "Fish & chips second para"
        );
        assert_eq!(html_to_text("1 &lt; 2 &#65;&#x42;"), "1 < 2 AB");
        assert_eq!(html_to_text(""), "");
    }

    const HOSTILE: &str = r#"<p>ok</p><script>alert(1)</script><img src="https://img.example/a.png" onerror="alert(1)"><a href="javascript:alert(1)">x</a>"#;

    fn assert_safe(out: &str) {
        assert!(!out.contains("script"), "{out}");
        assert!(!out.contains("onerror"), "{out}");
        assert!(!out.contains("javascript"), "{out}");
        assert!(out.contains("<p>ok</p>"), "{out}");
    }

    /// Z13-T1: every profile removes scripts, handlers and script URLs.
    #[test]
    fn every_profile_removes_script_handlers_and_script_urls() {
        for profile in [
            SanitizeProfile::RichText,
            SanitizeProfile::InboundEmail {
                allow_remote_images: false,
            },
            SanitizeProfile::InboundEmail {
                allow_remote_images: true,
            },
            SanitizeProfile::PortalPage,
            SanitizeProfile::CustomComponent,
        ] {
            assert_safe(&sanitize(HOSTILE, profile));
        }
    }

    #[test]
    fn rich_text_profile_is_todays_rules() {
        assert_eq!(
            sanitize(HOSTILE, SanitizeProfile::RichText),
            sanitize_rich_text(HOSTILE)
        );
    }

    #[test]
    fn inbound_email_loads_remote_images_only_when_chosen() {
        let blocked = sanitize(
            HOSTILE,
            SanitizeProfile::InboundEmail {
                allow_remote_images: false,
            },
        );
        assert!(!blocked.contains("<img"), "{blocked}");
        let allowed = sanitize(
            HOSTILE,
            SanitizeProfile::InboundEmail {
                allow_remote_images: true,
            },
        );
        assert!(
            allowed.contains(r#"<img src="https://img.example/a.png">"#),
            "{allowed}"
        );
        let table = sanitize(
            "<style>td{color:red}</style><table><tr><td colspan=\"2\">x</td></tr></table>",
            SanitizeProfile::InboundEmail {
                allow_remote_images: false,
            },
        );
        assert!(!table.contains("color"), "{table}");
        assert!(table.contains(r#"<td colspan="2">x</td>"#), "{table}");
    }

    #[test]
    fn portal_page_keeps_headings_tables_and_images() {
        let out = sanitize(
            r#"<h6>t</h6><figure><img src="https://img.example/a.png" alt="a"><figcaption>c</figcaption></figure><table><tr><th>h</th></tr></table>"#,
            SanitizeProfile::PortalPage,
        );
        for kept in ["<h6>", "<figure>", "<figcaption>", "<img", "<th>"] {
            assert!(out.contains(kept), "{kept} missing: {out}");
        }
    }

    #[test]
    fn custom_component_keeps_only_text_tags() {
        let out = sanitize(
            r#"<p class="x">a <strong>b</strong> <a href="https://x.example">l</a></p><h1>h</h1>"#,
            SanitizeProfile::CustomComponent,
        );
        assert_eq!(out, "<p>a <strong>b</strong> l</p>h");
    }

    /// Owner decision 4: `<noscript>` goes with its content — including
    /// markup nested inside it, whichever way the parser reads that content.
    #[test]
    fn noscript_is_removed_with_its_content() {
        let doc = "<html><body><noscript>enable js</noscript>                   <noscript><p>nested <b>fallback</b></p></noscript>                   <p>Hello world</p></body></html>";
        assert_eq!(html_to_text(doc), "Hello world");
        assert_eq!(
            sanitize_rich_text("<p>a</p><noscript><p>b</p></noscript>"),
            "<p>a</p>"
        );
    }
}

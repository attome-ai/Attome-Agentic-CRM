//! Email designs to email-safe HTML and plain text (roadmap E2-T2).
//!
//! A design is a list of blocks (the email designer's JSON, E2-T1):
//! `heading`, `text`, `image`, `button`, `divider`, `spacer` and `columns`.
//! [`render`] writes it as the two bodies of a Z13 template: HTML built from
//! nested tables with every style inline (what mail clients keep), and a
//! plain-text twin. Block text is Z13 template source, so `{{ first_name }}`
//! stays a placeholder that [`personalise`] fills per recipient, with the
//! HTML body escaping each value. Literal text outside `{{ }}` and `{% %}`
//! is escaped when the template is written, so a design never injects
//! markup.
//!
//! An Arabic (right-to-left) design sets `dir="rtl"` and right alignment on
//! every table and cell, so clients that ignore `dir` still lay it out
//! right. An image needs its alt text, and a link is `https:`, `http:`,
//! `mailto:`, `tel:` or a `{{ }}` placeholder; anything else refuses the
//! design.

use std::fmt::Write as _;

use attome_html::tmpl::{Output, RenderContext, Template};
use serde::{Deserialize, Serialize};

/// One block of a design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmailBlock {
    Heading {
        text: String,
        #[serde(default = "one")]
        level: u8,
    },
    Text {
        text: String,
    },
    Image {
        src: String,
        alt: String,
        #[serde(default)]
        href: Option<String>,
        #[serde(default)]
        width: Option<u32>,
    },
    Button {
        label: String,
        href: String,
    },
    Divider,
    Spacer {
        #[serde(default = "spacer_height")]
        height: u32,
    },
    Columns {
        columns: Vec<Vec<EmailBlock>>,
    },
    /// E25-T1: content chosen per recipient (`dynamic_blocks::resolve`);
    /// the renderer refuses it unresolved.
    Dynamic {
        id: String,
        variants: Vec<DynamicVariant>,
        #[serde(default)]
        default: Vec<EmailBlock>,
    },
}

/// One variant of a dynamic block: shown when its condition (Z11, over the
/// recipient's record) is true and, if set, the recipient is in `in_list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicVariant {
    pub id: String,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub in_list: Option<uuid::Uuid>,
    pub blocks: Vec<EmailBlock>,
}

fn one() -> u8 {
    1
}

fn spacer_height() -> u32 {
    16
}

/// Reading direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    #[default]
    Ltr,
    Rtl,
}

/// A whole design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailDesign {
    pub blocks: Vec<EmailBlock>,
    #[serde(default)]
    pub dir: Direction,
    /// The body width in pixels (600 by default).
    #[serde(default = "default_width")]
    pub width: u32,
    /// The brand colour for headings' accents and buttons (`#rrggbb`).
    #[serde(default = "default_colour")]
    pub primary_colour: String,
}

fn default_width() -> u32 {
    600
}

fn default_colour() -> String {
    "#1a56db".into()
}

/// The design as a Z13 template's two bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedEmail {
    pub html: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmailRenderError {
    #[error("an image needs its alt text")]
    MissingAlt,
    #[error("a link must be https:, http:, mailto:, tel: or a placeholder: {0}")]
    BadLink(String),
    #[error("the colour must be #rrggbb: {0}")]
    BadColour(String),
    #[error("columns may not hold columns")]
    NestedColumns,
    #[error("a dynamic block must be resolved for its recipient before rendering")]
    UnresolvedDynamic,
    #[error("the template does not compile: {0}")]
    Template(String),
}

/// `text` with HTML's special characters escaped, except inside `{{ }}`
/// and `{% %}` tags, which stay template source. Pure.
pub fn escape_outside_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        let next = [rest.find("{{"), rest.find("{%")]
            .into_iter()
            .flatten()
            .min();
        let Some(start) = next else {
            out.push_str(&escape(rest));
            break;
        };
        out.push_str(&escape(&rest[..start]));
        let close = if rest[start..].starts_with("{{") {
            "}}"
        } else {
            "%}"
        };
        match rest[start + 2..].find(close) {
            Some(end) => {
                let stop = start + 2 + end + 2;
                out.push_str(&rest[start..stop]);
                rest = &rest[stop..];
            }
            None => {
                out.push_str(&escape(&rest[start..]));
                break;
            }
        }
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn check_link(link: &str) -> Result<(), EmailRenderError> {
    let l = link.trim();
    let ok = ["https://", "http://", "mailto:", "tel:"]
        .iter()
        .any(|p| l.to_ascii_lowercase().starts_with(p))
        || l.starts_with("{{");
    if ok {
        Ok(())
    } else {
        Err(EmailRenderError::BadLink(link.to_owned()))
    }
}

fn check_colour(c: &str) -> Result<(), EmailRenderError> {
    let hex = c.strip_prefix('#').unwrap_or("");
    if hex.len() == 6 && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(EmailRenderError::BadColour(c.to_owned()))
    }
}

struct Writer<'a> {
    design: &'a EmailDesign,
    html: String,
    text: String,
}

impl Writer<'_> {
    fn align(&self) -> &'static str {
        match self.design.dir {
            Direction::Ltr => "left",
            Direction::Rtl => "right",
        }
    }

    fn row(&mut self, inner: &str) {
        let align = self.align();
        let _ = write!(
            self.html,
            "<tr><td align=\"{align}\" style=\"padding:8px 24px;text-align:{align};\">{inner}</td></tr>"
        );
    }

    fn blocks(&mut self, blocks: &[EmailBlock], nested: bool) -> Result<(), EmailRenderError> {
        for block in blocks {
            self.block(block, nested)?;
        }
        Ok(())
    }

    fn block(&mut self, block: &EmailBlock, nested: bool) -> Result<(), EmailRenderError> {
        let font = "font-family:Tahoma,Arial,sans-serif;";
        match block {
            EmailBlock::Heading { text, level } => {
                let size = match level {
                    1 => 26,
                    2 => 21,
                    _ => 17,
                };
                let level = (*level).clamp(1, 3);
                let inner = format!(
                    "<h{level} style=\"margin:0;{font}font-size:{size}px;line-height:1.3;color:#111827;\">{}</h{level}>",
                    escape_outside_tags(text)
                );
                self.row(&inner);
                let _ = write!(self.text, "{}\n\n", text.trim());
            }
            EmailBlock::Text { text } => {
                let paragraphs = text
                    .split("\n\n")
                    .map(|p| escape_outside_tags(p).replace('\n', "<br>"))
                    .map(|p| format!("<p style=\"margin:0 0 12px 0;{font}font-size:15px;line-height:1.6;color:#374151;\">{p}</p>"))
                    .collect::<String>();
                self.row(&paragraphs);
                let _ = write!(self.text, "{}\n\n", text.trim());
            }
            EmailBlock::Image {
                src,
                alt,
                href,
                width,
            } => {
                if alt.trim().is_empty() {
                    return Err(EmailRenderError::MissingAlt);
                }
                check_link(src)?;
                let max = self.design.width.saturating_sub(48);
                let width = width.unwrap_or(max).min(max);
                let img = format!(
                    "<img src=\"{}\" alt=\"{}\" width=\"{width}\" style=\"display:block;border:0;max-width:100%;height:auto;\">",
                    escape_outside_tags(src),
                    escape_outside_tags(alt)
                );
                let inner = match href {
                    Some(link) => {
                        check_link(link)?;
                        format!(
                            "<a href=\"{}\" target=\"_blank\">{img}</a>",
                            escape_outside_tags(link)
                        )
                    }
                    None => img,
                };
                self.row(&inner);
                let _ = write!(self.text, "[{}]\n\n", alt.trim());
            }
            EmailBlock::Button { label, href } => {
                check_link(href)?;
                let colour = &self.design.primary_colour;
                let inner = format!(
                    "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>\
                     <td bgcolor=\"{colour}\" style=\"border-radius:6px;\">\
                     <a href=\"{}\" target=\"_blank\" style=\"display:inline-block;padding:12px 24px;{font}font-size:15px;\
                     color:#ffffff;text-decoration:none;font-weight:bold;\">{}</a></td></tr></table>",
                    escape_outside_tags(href),
                    escape_outside_tags(label)
                );
                self.row(&inner);
                let _ = write!(self.text, "{}: {}\n\n", label.trim(), href.trim());
            }
            EmailBlock::Divider => {
                self.row("<hr style=\"border:0;border-top:1px solid #e5e7eb;margin:8px 0;\">");
                self.text.push_str("----\n\n");
            }
            EmailBlock::Spacer { height } => {
                let _ = write!(
                    self.html,
                    "<tr><td style=\"height:{h}px;line-height:{h}px;font-size:0;\">&nbsp;</td></tr>",
                    h = (*height).min(200)
                );
            }
            EmailBlock::Dynamic { .. } => return Err(EmailRenderError::UnresolvedDynamic),
            EmailBlock::Columns { columns } => {
                if nested {
                    return Err(EmailRenderError::NestedColumns);
                }
                let count = u32::try_from(columns.len().max(1)).unwrap_or(1);
                let percent = 100 / count;
                let dir = self.dir_attr();
                let mut cells = String::new();
                for column in columns {
                    let mut inner = Writer {
                        design: self.design,
                        html: String::new(),
                        text: String::new(),
                    };
                    inner.blocks(column, true)?;
                    let _ = write!(
                        cells,
                        "<td valign=\"top\" width=\"{percent}%\" style=\"width:{percent}%;\">\
                         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"{dir}>{}</table></td>",
                        inner.html
                    );
                    self.text.push_str(&inner.text);
                }
                let _ = write!(
                    self.html,
                    "<tr><td><table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"{dir}><tr>{cells}</tr></table></td></tr>"
                );
            }
        }
        Ok(())
    }

    fn dir_attr(&self) -> &'static str {
        match self.design.dir {
            Direction::Ltr => "",
            Direction::Rtl => " dir=\"rtl\"",
        }
    }
}

/// Writes a design as the HTML and text bodies of a Z13 template.
pub fn render(design: &EmailDesign) -> Result<RenderedEmail, EmailRenderError> {
    check_colour(&design.primary_colour)?;
    let mut w = Writer {
        design,
        html: String::new(),
        text: String::new(),
    };
    w.blocks(&design.blocks, false)?;
    let width = design.width.clamp(320, 800);
    let (dir, lang_dir) = match design.dir {
        Direction::Ltr => ("ltr", ""),
        Direction::Rtl => ("rtl", " dir=\"rtl\""),
    };
    let html = format!(
        "<!doctype html><html dir=\"{dir}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"></head>\
         <body style=\"margin:0;padding:0;background:#f3f4f6;\">\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#f3f4f6\"{lang_dir}>\
         <tr><td align=\"center\" style=\"padding:24px 8px;\">\
         <table role=\"presentation\" width=\"{width}\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#ffffff\" \
         style=\"width:{width}px;max-width:100%;background:#ffffff;border-radius:8px;\"{lang_dir}>{}</table>\
         </td></tr></table></body></html>",
        w.html
    );
    Ok(RenderedEmail {
        html,
        text: w.text.trim_end().to_owned(),
    })
}

/// Fills a rendered design for one recipient: the HTML body escapes every
/// value, the text body writes them as they are.
pub fn personalise(
    email: &RenderedEmail,
    schema: &attome_rules::Schema,
    values: attome_rules::Context,
    locale: &str,
) -> Result<RenderedEmail, EmailRenderError> {
    let compile = |source: &str| {
        Template::compile(source, schema).map_err(|e| EmailRenderError::Template(e.to_string()))
    };
    let html = compile(&email.html)?
        .render(&RenderContext::new(values.clone(), locale, Output::Html))
        .map_err(|e| EmailRenderError::Template(e.to_string()))?;
    let text = compile(&email.text)?
        .render(&RenderContext::new(values, locale, Output::Text))
        .map_err(|e| EmailRenderError::Template(e.to_string()))?;
    Ok(RenderedEmail { html, text })
}

#[cfg(test)]
mod email_render {
    use super::*;

    fn design(dir: Direction) -> EmailDesign {
        serde_json::from_value(serde_json::json!({
            "dir": dir,
            "blocks": [
                { "type": "heading", "text": "Hello {{ first_name }}", "level": 1 },
                { "type": "text", "text": "Your <b>offer</b> & more.\n\nSecond paragraph." },
                { "type": "image", "src": "https://cdn.example/banner.png", "alt": "Banner", "href": "https://example.com" },
                { "type": "button", "label": "Shop now", "href": "https://example.com/shop" },
                { "type": "columns", "columns": [
                    [{ "type": "text", "text": "Left" }],
                    [{ "type": "text", "text": "Right" }]
                ]},
                { "type": "divider" },
                { "type": "spacer", "height": 24 }
            ]
        }))
        .unwrap()
    }

    #[test]
    fn renders_email_safe_html_and_text() {
        let out = render(&design(Direction::Ltr)).unwrap();
        assert!(out.html.starts_with("<!doctype html><html dir=\"ltr\">"));
        assert!(out.html.contains("role=\"presentation\""));
        assert!(!out.html.contains("<style"), "every style is inline");
        assert!(
            out.html.contains("Hello {{ first_name }}"),
            "placeholders stay template source"
        );
        assert!(
            out.html
                .contains("Your &lt;b&gt;offer&lt;/b&gt; &amp; more.")
        );
        assert!(out.html.contains("alt=\"Banner\""));
        assert!(out.html.contains("text-align:left;"));
        assert!(out.html.contains("width=\"50%\""));
        assert_eq!(
            out.text,
            "Hello {{ first_name }}\n\nYour <b>offer</b> & more.\n\nSecond paragraph.\n\n[Banner]\n\n\
             Shop now: https://example.com/shop\n\nLeft\n\nRight\n\n----"
        );
    }

    #[test]
    fn arabic_designs_run_right_to_left() {
        let out = render(&design(Direction::Rtl)).unwrap();
        assert!(out.html.contains("<html dir=\"rtl\">"));
        assert!(out.html.contains("text-align:right;"));
        assert!(
            out.html.matches("dir=\"rtl\"").count() >= 3,
            "every table says rtl"
        );
        assert!(!out.html.contains("text-align:left;"));
    }

    #[test]
    fn refuses_missing_alt_text_and_unsafe_links() {
        let mut d = design(Direction::Ltr);
        d.blocks = vec![EmailBlock::Image {
            src: "https://cdn.example/a.png".into(),
            alt: " ".into(),
            href: None,
            width: None,
        }];
        assert_eq!(render(&d), Err(EmailRenderError::MissingAlt));
        d.blocks = vec![EmailBlock::Button {
            label: "Go".into(),
            href: "javascript:alert(1)".into(),
        }];
        assert!(matches!(render(&d), Err(EmailRenderError::BadLink(_))));
        d.blocks = vec![EmailBlock::Columns {
            columns: vec![vec![EmailBlock::Columns { columns: vec![] }]],
        }];
        assert_eq!(render(&d), Err(EmailRenderError::NestedColumns));
    }

    #[test]
    fn tags_are_kept_and_text_around_them_escaped() {
        assert_eq!(
            escape_outside_tags("a < {{ x > 1 }} & {% if y %}b{% end %}"),
            "a &lt; {{ x > 1 }} &amp; {% if y %}b{% end %}"
        );
        assert_eq!(escape_outside_tags("{{ unclosed <"), "{{ unclosed &lt;");
    }

    #[test]
    fn personalises_per_recipient() {
        let out = render(&design(Direction::Ltr)).unwrap();
        let schema = attome_rules::Schema::new().with_field("first_name", attome_rules::Type::Text);
        let ctx = attome_rules::Context::new(chrono::Utc::now())
            .with_field("first_name", attome_rules::Value::Text("Sara <3".into()));
        let mail = personalise(&out, &schema, ctx, "en").unwrap();
        assert!(mail.html.contains("Hello Sara &lt;3"));
        assert!(mail.text.starts_with("Hello Sara <3"));
    }
}

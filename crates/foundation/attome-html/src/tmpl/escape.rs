//! How a value is written into the output, by where it lands (Z13-T2,
//! Z13-T3; Z13-T4 adds region formatting).
//!
//! HTML output tracks, over the template's own literal text, whether the
//! next value lands in text, inside a tag, inside a quoted attribute, or
//! inside a URL attribute (`href`, `src`, `action`, `formaction`), and
//! escapes it for that place:
//! - **text**: `&`, `<`, `>` (and quotes) as entities;
//! - **attribute**: quotes too, so a value cannot close the attribute;
//! - **inside a tag, unquoted**: also spaces, `=`, `/` and backticks, so a
//!   value cannot start another attribute;
//! - **URL**: only `http`, `https`, `mailto` and `tel` schemes, or a relative
//!   URL; anything else (`javascript:`, `data:`) becomes `#`; the rest is
//!   percent-encoded where it is not URL-safe, then entity-escaped.
//!
//! Text output escapes nothing and strips control characters (tabs and line
//! breaks stay).

use attome_rules::Value;

/// What a template renders to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// Values escaped for where they land in the HTML.
    Html,
    /// Values as is, control characters stripped (a plain-text email).
    Text,
    /// Text for an SMS (Z13-T5): as `Text`; the set counts its segments.
    Sms,
    /// Text for a WhatsApp message (Z13-T5): as `Text`.
    Whatsapp,
}

/// Where in HTML the next value lands.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum HtmlPlace {
    #[default]
    Text,
    /// Inside a tag, between attributes; `name` is the attribute being read.
    Tag { name: String, after_equals: bool },
    /// Inside a quoted attribute value.
    Attribute { quote: char, url: bool },
}

const URL_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "action",
    "formaction",
    "xlink:href",
    "poster",
];

impl HtmlPlace {
    /// Moves over literal template text (values never move it: they are
    /// escaped for where they land).
    pub(crate) fn advance(&mut self, literal: &str) {
        let mut chars = literal.chars().peekable();
        while let Some(c) = chars.next() {
            *self = match std::mem::take(self) {
                HtmlPlace::Text => {
                    if c == '<'
                        && chars
                            .peek()
                            .is_some_and(|n| n.is_ascii_alphabetic() || *n == '/')
                    {
                        HtmlPlace::Tag {
                            name: String::new(),
                            after_equals: false,
                        }
                    } else {
                        HtmlPlace::Text
                    }
                }
                HtmlPlace::Tag {
                    mut name,
                    after_equals,
                } => match c {
                    '>' => HtmlPlace::Text,
                    '"' | '\'' if after_equals => HtmlPlace::Attribute {
                        quote: c,
                        url: URL_ATTRIBUTES.contains(&name.to_ascii_lowercase().as_str()),
                    },
                    '=' => HtmlPlace::Tag {
                        name,
                        after_equals: true,
                    },
                    c if c.is_whitespace() => HtmlPlace::Tag {
                        name: if after_equals { name } else { String::new() },
                        after_equals,
                    },
                    c => {
                        if after_equals {
                            // An unquoted value: it ends at the next space.
                            HtmlPlace::Tag {
                                name: String::new(),
                                after_equals: false,
                            }
                        } else {
                            name.push(c);
                            HtmlPlace::Tag {
                                name,
                                after_equals: false,
                            }
                        }
                    }
                },
                HtmlPlace::Attribute { quote, url } => {
                    if c == quote {
                        HtmlPlace::Tag {
                            name: String::new(),
                            after_equals: false,
                        }
                    } else {
                        HtmlPlace::Attribute { quote, url }
                    }
                }
            };
        }
    }
}

/// A value as text: nothing for null, whole numbers without a fraction,
/// a list's elements joined by ", ".
pub(crate) fn display(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                n.to_string()
            }
        }
        Value::Text(s) | Value::Choice(s) => s.clone(),
        Value::Date(d) => d.to_rfc3339(),
        Value::Lookup(id) => id.to_string(),
        Value::List(items) => items.iter().map(display).collect::<Vec<_>>().join(", "),
        Value::Record(fields) => fields
            .iter()
            .map(|(_, v)| display(v))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn entities(text: &str, extra: &[char]) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if extra.contains(&c) || (extra.contains(&' ') && c.is_whitespace()) => {
                out.push_str(&format!("&#{};", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

/// A URL value made safe: an allowed scheme or relative, percent-encoded
/// where it is not URL-safe.
fn safe_url(text: &str) -> String {
    let trimmed = text.trim();
    let scheme = trimmed
        .split_once(':')
        .map(|(s, _)| s)
        .filter(|s| !s.contains(['/', '?', '#']));
    if let Some(scheme) = scheme
        && !["http", "https", "mailto", "tel"]
            .iter()
            .any(|ok| scheme.eq_ignore_ascii_case(ok))
    {
        return "#".to_owned();
    }
    let mut out = String::with_capacity(trimmed.len());
    for byte in trimmed.bytes() {
        let keep = byte.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&byte);
        if keep && byte != b'\'' && byte != b'"' {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn without_controls(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

/// A value written for `output`, landing at `place` in HTML.
pub(crate) fn write(value: &Value, output: Output, place: &HtmlPlace) -> String {
    let text = display(value);
    match output {
        Output::Text | Output::Sms | Output::Whatsapp => without_controls(&text),
        Output::Html => match place {
            HtmlPlace::Text => entities(&text, &[]),
            HtmlPlace::Attribute { url: false, .. } => entities(&text, &[]),
            HtmlPlace::Attribute { url: true, .. } => entities(&safe_url(&text), &[]),
            HtmlPlace::Tag { .. } => entities(&text, &[' ', '=', '/', '`']),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: &str = "\"><script>alert(1)</script>";

    fn place_after(literal: &str) -> HtmlPlace {
        let mut place = HtmlPlace::default();
        place.advance(literal);
        place
    }

    fn hostile(place: &HtmlPlace) -> String {
        write(&Value::Text(HOSTILE.into()), Output::Html, place)
    }

    #[test]
    fn escape_in_text() {
        let out = hostile(&place_after("<p>Hello "));
        assert_eq!(out, "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;");
        assert!(!out.contains('<'));
    }

    #[test]
    fn escape_in_an_attribute() {
        let place = place_after("<p title=\"");
        assert_eq!(
            place,
            HtmlPlace::Attribute {
                quote: '"',
                url: false
            }
        );
        let out = hostile(&place);
        assert!(!out.contains('"') && !out.contains('<'), "{out}");
        assert_eq!(place_after("<p title=\"x\">"), HtmlPlace::Text);
    }

    #[test]
    fn escape_in_a_url() {
        let place = place_after("<a href=\"");
        assert_eq!(
            place,
            HtmlPlace::Attribute {
                quote: '"',
                url: true
            }
        );
        assert_eq!(
            write(
                &Value::Text("javascript:alert(1)".into()),
                Output::Html,
                &place
            ),
            "#"
        );
        assert_eq!(
            write(
                &Value::Text("data:text/html,x".into()),
                Output::Html,
                &place
            ),
            "#"
        );
        assert_eq!(
            write(
                &Value::Text("https://a.test/x y".into()),
                Output::Html,
                &place
            ),
            "https://a.test/x%20y"
        );
        let out = hostile(&place);
        assert!(!out.contains('"') && !out.contains('<'), "{out}");
        assert_eq!(
            write(&Value::Text("/orders/1".into()), Output::Html, &place),
            "/orders/1"
        );
    }

    #[test]
    fn escape_inside_a_tag() {
        let out = write(
            &Value::Text("x onclick=alert(1)".into()),
            Output::Html,
            &place_after("<div "),
        );
        assert!(!out.contains(' ') && !out.contains('='), "{out}");
    }

    #[test]
    fn escape_nothing_in_text_output_but_controls() {
        assert_eq!(
            write(
                &Value::Text(format!("{HOSTILE}\u{7}\nok")),
                Output::Text,
                &HtmlPlace::Text
            ),
            format!("{HOSTILE}\nok")
        );
    }

    #[test]
    fn values_display_plainly() {
        assert_eq!(display(&Value::Null), "");
        assert_eq!(display(&Value::Number(3.0)), "3");
        assert_eq!(display(&Value::Number(2.5)), "2.5");
        assert_eq!(
            display(&Value::List(vec![
                Value::Text("a".into()),
                Value::Number(1.0)
            ])),
            "a, 1"
        );
    }
}

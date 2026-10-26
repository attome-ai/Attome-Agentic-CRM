//! Escaping a value for HTML, the text primitive every HTML-writing crate
//! needs. The `{{name}}` placeholder merge that lived beside it moved onto
//! the template engine (Z13-T8): `crate::tmpl::Template::placeholders`.

/// Minimal HTML entity escaping for interpolating untrusted text into an
/// element body or a quoted attribute value: `&`, `<`, `>`, `"` and `'`.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_html_escapes_the_five_characters() {
        assert_eq!(
            escape_html(r#"<a href="x">Tom & 'Jerry'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;Tom &amp; &#39;Jerry&#39;&lt;/a&gt;"
        );
        assert_eq!(escape_html("plain سلام"), "plain سلام");
    }
}

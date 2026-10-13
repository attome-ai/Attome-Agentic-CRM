//! The two text primitives every template-rendering crate needs: escaping a
//! value for HTML, and substituting `{{name}}` placeholders.
//!
//! They were copied into attome-email, xrm-docgen, xrm-notification and
//! trd-engine, and the copies of the placeholder merge had drifted apart on
//! what an unknown name renders as. One implementation here, with the
//! unknown-name rule decided by each caller's lookup, not by the merge.

use std::borrow::Cow;

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

/// Replaces every `{{ name }}` placeholder in `template` with `lookup(name)`.
///
/// **The one rule for unknown names:** when `lookup` returns `None`, the
/// placeholder is left in the output exactly as written. A caller that wants
/// unknown names to render empty returns `Some("")` for them instead — the
/// merge never guesses, so each caller's contract is visible in its closure.
///
/// Details, all deliberate:
/// - `name` is the text between the braces with surrounding whitespace
///   trimmed, so `{{name}}` and `{{ name }}` are the same placeholder.
/// - Single pass: a substituted value is never scanned again, so a value that
///   itself contains `{{other}}` is emitted literally rather than expanded.
///   (Repeated whole-string replacement expanded it, in whatever order a
///   `HashMap` iterated — nondeterministic, and an injection path.)
/// - Leftmost match: when a candidate is rejected (`lookup` returns `None`),
///   scanning resumes one character later, so `{{{name}}}` renders as
///   `{value}` and `{{a {{b}}` still finds `{{b}}` — the same matches a
///   `\{\{\s*name\s*\}\}` regex finds.
/// - Values are inserted as returned. Escaping (for an HTML template) is the
///   lookup's job, because only the caller knows the output format.
pub fn merge_placeholders<'v, F>(template: &str, mut lookup: F) -> String
where
    F: FnMut(&str) -> Option<Cow<'v, str>>,
{
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            break;
        };
        match lookup(after_open[..close].trim()) {
            Some(value) => {
                out.push_str(&rest[..open]);
                out.push_str(&value);
                rest = &after_open[close + 2..];
            }
            None => {
                // Keep the first `{` and retry from the next character.
                out.push_str(&rest[..=open]);
                rest = &rest[open + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn merge_keep(t: &str, v: &HashMap<String, String>) -> String {
        merge_placeholders(t, |n| v.get(n).map(|s| Cow::Borrowed(s.as_str())))
    }

    #[test]
    fn escape_html_escapes_the_five_characters() {
        assert_eq!(
            escape_html(r#"<a href="x">Tom & 'Jerry'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;Tom &amp; &#39;Jerry&#39;&lt;/a&gt;"
        );
        assert_eq!(escape_html("plain سلام"), "plain سلام");
    }

    #[test]
    fn known_placeholders_are_replaced_with_or_without_spaces() {
        let v = vars(&[("name", "Ada"), ("amount", "42")]);
        assert_eq!(
            merge_keep("Hi {{name}}, you have {{ amount }} credits.", &v),
            "Hi Ada, you have 42 credits."
        );
    }

    #[test]
    fn unknown_placeholders_are_kept_verbatim() {
        let v = vars(&[("name", "Ada")]);
        assert_eq!(
            merge_keep("Hi {{name}}, ref {{ unknown }}.", &v),
            "Hi Ada, ref {{ unknown }}."
        );
        assert_eq!(merge_keep("Hi {{name}}.", &HashMap::new()), "Hi {{name}}.");
    }

    #[test]
    fn a_lookup_can_render_unknown_names_empty() {
        let out = merge_placeholders("a{{x}}b{{ y }}c", |_| Some(Cow::Borrowed("")));
        assert_eq!(out, "abc");
    }

    #[test]
    fn substituted_values_are_not_expanded_again() {
        let v = vars(&[("a", "{{b}}"), ("b", "B")]);
        assert_eq!(merge_keep("{{a}} {{b}}", &v), "{{b}} B");
    }

    #[test]
    fn matching_is_leftmost_after_a_rejected_candidate() {
        let v = vars(&[("name", "Ada"), ("b", "B")]);
        assert_eq!(merge_keep("{{{name}}}", &v), "{Ada}");
        assert_eq!(merge_keep("{{a {{b}}", &v), "{{a B");
    }

    #[test]
    fn unterminated_and_empty_input_pass_through() {
        let v = vars(&[("name", "Ada")]);
        assert_eq!(merge_keep("Hi {{name", &v), "Hi {{name");
        assert_eq!(merge_keep("", &v), "");
        assert_eq!(merge_keep("no placeholders", &v), "no placeholders");
    }

    #[test]
    fn multibyte_text_around_placeholders_is_preserved() {
        let v = vars(&[("name", "أحمد")]);
        assert_eq!(merge_keep("مرحبا {{name}}!", &v), "مرحبا أحمد!");
    }
}

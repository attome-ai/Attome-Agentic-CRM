//! One message in every language and output (roadmap Z13-T5): a
//! [`TemplateSet`] holds a template's variants by (language, output), its
//! layouts and its partials.
//!
//! **Variants.** [`TemplateSet::render`] picks the variant for the asked
//! language and output; without one, the default language's; without
//! either, the HTML variant (asked language, then default) rendered and
//! stripped to text. HTML itself never falls back to text.
//!
//! **Layouts and partials.** `{% layout 'name' %}` (first in a template)
//! puts the template where the layout says `{% body %}`; `{% include 'name' %}`
//! inserts a partial. Both expand before compiling, at most
//! [`MAX_EXPANSION_DEPTH`] deep, so a partial that includes itself is an
//! error, not a loop.
//!
//! **SMS.** An SMS render also counts its segments: GSM-7 text (Latin
//! letters, digits and the GSM symbols) is 160 characters in one segment and
//! 153 a segment when split; anything else, Arabic included, is UCS-2: 70
//! characters in one, 67 a segment when split.

use std::collections::BTreeMap;

use attome_rules::Schema;

use super::{Output, Position, RenderContext, Template, TemplateError};

/// How deep layouts and includes may nest.
pub const MAX_EXPANSION_DEPTH: usize = 5;

/// A rendered variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub text: String,
    /// The variant used: its language and output.
    pub language: String,
    pub output: Output,
    /// Whether an HTML variant was stripped to text for want of a text one.
    pub stripped_from_html: bool,
    /// For SMS output, its segments.
    pub sms: Option<SmsCount>,
}

/// How an SMS text is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmsEncoding {
    Gsm7,
    Ucs2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmsCount {
    pub encoding: SmsEncoding,
    /// GSM-7 septets or UTF-16 units.
    pub units: usize,
    pub segments: usize,
}

const GSM7_BASIC: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
/// Characters GSM-7 sends as two septets (an escape, then the character).
const GSM7_EXTENSION: &str = "^{}\\[~]|€\u{c}";

/// The segments `text` takes as an SMS.
pub fn sms_segments(text: &str) -> SmsCount {
    let mut septets = 0;
    let mut gsm = true;
    for c in text.chars() {
        if GSM7_BASIC.contains(c) {
            septets += 1;
        } else if GSM7_EXTENSION.contains(c) {
            septets += 2;
        } else {
            gsm = false;
            break;
        }
    }
    let (encoding, units, single, split) = if gsm {
        (SmsEncoding::Gsm7, septets, 160, 153)
    } else {
        (SmsEncoding::Ucs2, text.encode_utf16().count(), 70, 67)
    };
    let segments = if units == 0 {
        0
    } else if units <= single {
        1
    } else {
        units.div_ceil(split)
    };
    SmsCount {
        encoding,
        units,
        segments,
    }
}

/// A template's variants, layouts and partials.
#[derive(Debug, Clone, Default)]
pub struct TemplateSet {
    pub default_language: String,
    /// Source by (language, output).
    pub variants: BTreeMap<(String, OutputKey), String>,
    pub layouts: BTreeMap<String, String>,
    pub partials: BTreeMap<String, String>,
}

/// [`Output`] as a map key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OutputKey {
    Html,
    Text,
    Sms,
    Whatsapp,
}

impl From<Output> for OutputKey {
    fn from(output: Output) -> Self {
        match output {
            Output::Html => Self::Html,
            Output::Text => Self::Text,
            Output::Sms => Self::Sms,
            Output::Whatsapp => Self::Whatsapp,
        }
    }
}

fn syntax(message: impl Into<String>) -> TemplateError {
    TemplateError::Syntax {
        at: Position { line: 1, column: 1 },
        message: message.into(),
    }
}

/// The name in `'name'` or `"name"`.
fn quoted(arg: &str) -> Option<&str> {
    let arg = arg.trim();
    let inner = arg
        .strip_prefix('\'')
        .and_then(|a| a.strip_suffix('\''))
        .or_else(|| arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')))?;
    (!inner.is_empty()).then_some(inner)
}

/// The first `{% word ... %}` tag of `source` at or after `from`:
/// (start, end, argument).
fn find_tag<'a>(source: &'a str, word: &str, from: usize) -> Option<(usize, usize, &'a str)> {
    let mut at = from;
    while let Some(open) = source[at..].find("{%") {
        let start = at + open;
        let close = source[start..].find("%}")? + start;
        let inner = source[start + 2..close].trim();
        if let Some(rest) = inner.strip_prefix(word)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return Some((start, close + 2, rest.trim()));
        }
        at = close + 2;
    }
    None
}

impl TemplateSet {
    /// `source` with its layout and includes expanded.
    fn expand(&self, source: &str, depth: usize) -> Result<String, TemplateError> {
        if depth > MAX_EXPANSION_DEPTH {
            return Err(syntax(format!(
                "layouts and includes nest at most {MAX_EXPANSION_DEPTH} deep"
            )));
        }
        let mut body = source.to_owned();
        // Includes first, each expanded in turn.
        let mut from = 0;
        while let Some((start, end, arg)) = find_tag(&body, "include", from) {
            let name = quoted(arg)
                .ok_or_else(|| syntax("include names a partial: {% include 'name' %}"))?;
            let partial = self
                .partials
                .get(name)
                .ok_or_else(|| syntax(format!("no partial named {name}")))?;
            let expanded = self.expand(partial, depth + 1)?;
            body.replace_range(start..end, &expanded);
            from = start + expanded.len();
        }
        // Then the layout, if the template starts with one.
        if let Some((start, end, arg)) = find_tag(&body, "layout", 0)
            && body[..start].trim().is_empty()
        {
            let name =
                quoted(arg).ok_or_else(|| syntax("layout names a layout: {% layout 'name' %}"))?;
            let layout = self
                .layouts
                .get(name)
                .ok_or_else(|| syntax(format!("no layout named {name}")))?;
            let inner = body[end..].to_owned();
            let wrapper = self.expand(layout, depth + 1)?;
            let (b_start, b_end, _) = find_tag(&wrapper, "body", 0)
                .ok_or_else(|| syntax(format!("layout {name} has no {{% body %}}")))?;
            let mut out = wrapper;
            out.replace_range(b_start..b_end, &inner);
            return Ok(out);
        }
        Ok(body)
    }

    /// The (language, source) of the variant for `language` and `output`,
    /// or the default language's.
    fn variant(&self, language: &str, output: Output) -> Option<(String, String)> {
        let key = OutputKey::from(output);
        [language, self.default_language.as_str()]
            .into_iter()
            .find_map(|lang| {
                self.variants
                    .get(&(lang.to_owned(), key))
                    .map(|source| (lang.to_owned(), source.clone()))
            })
    }

    /// Renders the variant for `language` and `ctx.output` (see the module
    /// doc for the fallback order), compiled against `schema`.
    pub fn render(
        &self,
        language: &str,
        schema: &Schema,
        ctx: &RenderContext,
    ) -> Result<Rendered, TemplateError> {
        let (used, source, output, stripped) = match self.variant(language, ctx.output) {
            Some((lang, source)) => (lang, source, ctx.output, false),
            None if ctx.output != Output::Html => {
                let (lang, source) = self
                    .variant(language, Output::Html)
                    .ok_or_else(|| syntax(format!("no variant for {language}")))?;
                (lang, source, Output::Html, true)
            }
            None => return Err(syntax(format!("no HTML variant for {language}"))),
        };
        let expanded = self.expand(&source, 0)?;
        let template = Template::compile(&expanded, schema)?;
        let mut render_ctx = ctx.clone();
        render_ctx.output = output;
        let mut text = template.render(&render_ctx)?;
        if stripped {
            text = html_to_text(&text);
        }
        let output = if stripped { ctx.output } else { output };
        Ok(Rendered {
            sms: (output == Output::Sms).then(|| sms_segments(&text)),
            text,
            language: used,
            output,
            stripped_from_html: stripped,
        })
    }
}

/// HTML's visible text, whitespace runs folded.
fn html_to_text(html: &str) -> String {
    let fragment = scraper::Html::parse_fragment(html);
    let text: String = fragment.root_element().text().collect();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use attome_rules::{Context, Type, Value};
    use chrono::Utc;

    use super::*;

    fn set() -> TemplateSet {
        let mut variants = BTreeMap::new();
        variants.insert(
            ("en".to_owned(), OutputKey::Html),
            "{% layout 'mail' %}<p>Hello <b>{{ name }}</b></p>".to_owned(),
        );
        variants.insert(
            ("ar".to_owned(), OutputKey::Html),
            "<p>مرحبا {{ name }}</p>".to_owned(),
        );
        variants.insert(
            ("en".to_owned(), OutputKey::Sms),
            "Hi {{ name }}".to_owned(),
        );
        TemplateSet {
            default_language: "en".to_owned(),
            variants,
            layouts: [(
                "mail".to_owned(),
                "<html><body>{% body %}{% include 'footer' %}</body></html>".to_owned(),
            )]
            .into_iter()
            .collect(),
            partials: [("footer".to_owned(), "<footer>Attome</footer>".to_owned())]
                .into_iter()
                .collect(),
        }
    }

    fn render(
        set: &TemplateSet,
        language: &str,
        output: Output,
    ) -> Result<Rendered, TemplateError> {
        let schema = Schema::new().with_field("name", Type::Text);
        let values = Context::new(Utc::now()).with_field("name", Value::Text("Salma".into()));
        set.render(
            language,
            &schema,
            &RenderContext::new(values, language, output),
        )
    }

    #[test]
    fn variants_fall_back_in_order() {
        let set = set();
        let ar = render(&set, "ar", Output::Html).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((ar.language.as_str(), ar.stripped_from_html), ("ar", false));
        // No Arabic SMS: the default language's.
        let sms = render(&set, "ar", Output::Sms).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            (sms.language.as_str(), sms.text.as_str()),
            ("en", "Hi Salma")
        );
        // No text variant at all: the Arabic HTML, stripped.
        let text = render(&set, "ar", Output::Text).unwrap_or_else(|e| panic!("{e}"));
        assert!(text.stripped_from_html);
        assert_eq!(text.text, "مرحبا Salma");
        // The layout and its partial wrap the English HTML.
        let en = render(&set, "en", Output::Html).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            en.text,
            "<html><body><p>Hello <b>Salma</b></p><footer>Attome</footer></body></html>"
        );
        let empty = TemplateSet::default();
        assert!(render(&empty, "en", Output::Html).is_err());
    }

    #[test]
    fn variants_include_depth_is_limited() {
        let mut set = set();
        set.partials
            .insert("loop".to_owned(), "x{% include 'loop' %}".to_owned());
        set.variants.insert(
            ("en".to_owned(), OutputKey::Text),
            "{% include 'loop' %}".to_owned(),
        );
        let err = render(&set, "en", Output::Text).unwrap_err();
        assert_eq!(err.code(), "template.syntax");
        // Five levels are fine.
        let mut deep = set.clone();
        for n in 0..4 {
            deep.partials
                .insert(format!("p{n}"), format!("{n}{{% include 'p{}' %}}", n + 1));
        }
        deep.partials.insert("p4".to_owned(), "4".to_owned());
        deep.variants.insert(
            ("en".to_owned(), OutputKey::Text),
            "{% include 'p0' %}".to_owned(),
        );
        assert_eq!(
            render(&deep, "en", Output::Text)
                .unwrap_or_else(|e| panic!("{e}"))
                .text,
            "01234"
        );
    }

    #[test]
    fn variants_count_arabic_sms_segments() {
        let arabic = "مرحبا بك في أتوم، طلبك رقم ١٢٣٤ جاهز للاستلام من الفرع الرئيسي غدا صباحا";
        let count = sms_segments(arabic);
        assert_eq!(count.encoding, SmsEncoding::Ucs2);
        assert_eq!(count.units, arabic.encode_utf16().count());
        assert_eq!(
            count.segments,
            if count.units <= 70 {
                1
            } else {
                count.units.div_ceil(67)
            }
        );
        let long_arabic = "م".repeat(140);
        assert_eq!(
            sms_segments(&long_arabic).segments,
            3,
            "140 UCS-2 units: 67 + 67 + 6"
        );
        let latin = sms_segments(&"a".repeat(160));
        assert_eq!((latin.encoding, latin.segments), (SmsEncoding::Gsm7, 1));
        assert_eq!(sms_segments(&"a".repeat(161)).segments, 2);
        assert_eq!(
            sms_segments("{}").units,
            4,
            "extension characters take two septets"
        );
        let sms = render(&set(), "en", Output::Sms).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sms.sms.map(|s| s.segments), Some(1));
    }
}

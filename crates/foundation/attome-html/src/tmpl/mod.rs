//! The one template language (roadmap Z13-T2): literal text with
//! `{{ expression }}` output, `{% if expression %}...{% else %}...{% end %}`
//! and `{% for item in expression limit N %}...{% end %}`, every expression a
//! V2 rule expression compiled and evaluated by `attome-rules` (D-399: there
//! is no second evaluator).
//!
//! A template is compiled once against the [`Schema`] of the values it will
//! see ([`Template::compile`]): an unknown field, a non-bool condition or a
//! loop over something that is not a list fails then, with its line and
//! column. Rendering ([`Template::render`]) takes a [`RenderContext`]: the
//! values (an `attome_rules::Context`), the locale and the output kind.
//! HTML output escapes every value; text output writes it as is.
//!
//! A loop names its limit, at most [`MAX_LOOP_LIMIT`]; a list longer than its
//! limit is an error, never silently cut short. Inside a loop the item is a
//! field (`{{ line }}`), and a record item's fields read as `line.qty`.
//!
//! An output may end with region filters (Z13-T4),
//! `{{ total | currency('SAR') }}`, `{{ due | hijri }}`, `{{ n | number(2) }}`,
//! `{{ opened | date('long') }}`, `{{ code | digits('western') }}`, formatted
//! for the render's locale. `{% dir %}...{% end %}` wraps a block in
//! `<div dir="rtl" lang="ar">` for an Arabic locale (`dir="ltr"` otherwise) in
//! HTML output, and writes the block alone in text output.

mod escape;
mod format;
mod parse;
mod render;
mod set;

pub use escape::Output;
pub use format::MAX_DECIMALS;
pub use parse::MAX_LOOP_LIMIT;
pub use render::{RenderContext, RenderLimits};
pub use set::{
    MAX_EXPANSION_DEPTH, OutputKey, Rendered, SmsCount, SmsEncoding, TemplateSet, sms_segments,
};

/// Which render limit stopped a render (Z13-T6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderLimit {
    Time,
    Output,
    Iterations,
}

use attome_rules::{RulesError, Schema};

/// Where in the template source something went wrong (1-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl Position {
    /// The line and column of byte `offset` in `source`.
    pub(crate) fn of(source: &str, offset: usize) -> Self {
        let before = &source[..offset.min(source.len())];
        let line = before.matches('\n').count() + 1;
        let column = before
            .rsplit_once('\n')
            .map_or(before, |(_, last)| last)
            .chars()
            .count()
            + 1;
        Self { line, column }
    }
}

impl std::fmt::Display for Position {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

/// Why a template did not compile or render.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TemplateError {
    /// The template's own syntax: an unclosed tag, a stray `{% end %}`, a
    /// loop without its limit.
    #[error("template syntax at {at}: {message}")]
    Syntax { at: Position, message: String },
    /// An expression did not compile or failed to evaluate.
    #[error("template expression at {at}: {error}")]
    Expression { at: Position, error: RulesError },
    /// A loop's list is longer than its limit.
    #[error("template loop at {at}: {len} items, over its limit of {limit}")]
    LimitExceeded {
        at: Position,
        limit: usize,
        len: usize,
    },
    /// The render ran past one of its [`RenderLimits`] (Z13-T6).
    #[error("template render stopped near {at}: over its {limit:?} limit")]
    RenderLimit { at: Position, limit: RenderLimit },
}

impl TemplateError {
    /// A stable code, like `rules.*` for expressions.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Syntax { .. } => "template.syntax",
            Self::Expression { error, .. } => error.code(),
            Self::LimitExceeded { .. } => "template.loop.limit_exceeded",
            Self::RenderLimit {
                limit: RenderLimit::Time,
                ..
            } => "template.limit.time",
            Self::RenderLimit {
                limit: RenderLimit::Output,
                ..
            } => "template.limit.output",
            Self::RenderLimit {
                limit: RenderLimit::Iterations,
                ..
            } => "template.limit.iterations",
        }
    }

    /// Where it happened.
    pub fn position(&self) -> Position {
        match self {
            Self::Syntax { at, .. }
            | Self::Expression { at, .. }
            | Self::LimitExceeded { at, .. }
            | Self::RenderLimit { at, .. } => *at,
        }
    }
}

/// A compiled template.
#[derive(Debug, Clone)]
pub struct Template {
    nodes: Vec<parse::Node>,
}

impl Template {
    /// Parses `source` and compiles every expression against `schema`.
    pub fn compile(source: &str, schema: &Schema) -> Result<Self, TemplateError> {
        Ok(Self {
            nodes: parse::parse(source, schema)?,
        })
    }

    /// Renders with `ctx`'s values, locale and output kind.
    pub fn render(&self, ctx: &RenderContext) -> Result<String, TemplateError> {
        render::render(&self.nodes, ctx)
    }

    /// Z13-T8: a template whose only syntax is `{{ name }}` placeholders,
    /// for the stored notification and document templates written before the
    /// template language. Each `{{ name }}` that `is_field` accepts renders
    /// field `name` of the render's values (nothing when it has none),
    /// escaped for where it lands like any output; one it rejects, and all
    /// other text, `{%` included, stays as written. So the caller's rule for
    /// an unknown name is its `is_field`: reject it to keep it verbatim, or
    /// accept it and leave the field unset to render it empty.
    pub fn placeholders(source: &str, is_field: impl FnMut(&str) -> bool) -> Self {
        Self {
            nodes: parse::placeholders(source, is_field),
        }
    }

    /// The field names a [`Self::placeholders`] template renders, in order of
    /// appearance (repeats included).
    pub fn placeholder_names(&self) -> impl Iterator<Item = &str> {
        self.nodes.iter().filter_map(|node| match node {
            parse::Node::Field(name) => Some(name.as_str()),
            _ => None,
        })
    }
}

#[cfg(test)]
mod placeholder_tests {
    //! Z13-T8: the cases the `{{name}}` merge was pinned by, unchanged in
    //! their expected output.
    use super::*;
    use attome_rules::{Context, Value};
    use std::collections::HashMap;

    fn vars(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn values(v: &HashMap<String, String>) -> Context {
        v.iter()
            .fold(Context::new(chrono::Utc::now()), |c, (k, v)| {
                c.with_field(k.clone(), Value::Text(v.clone()))
            })
    }

    /// Unknown names kept verbatim, values as given.
    fn merge_keep(t: &str, v: &HashMap<String, String>) -> String {
        Template::placeholders(t, |n| v.contains_key(n))
            .render(&RenderContext::new(values(v), "en", Output::Text))
            .unwrap()
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
    fn an_accepted_name_without_a_value_renders_empty() {
        let out = Template::placeholders("a{{x}}b{{ y }}c", |_| true)
            .render(&RenderContext::new(
                Context::new(chrono::Utc::now()),
                "en",
                Output::Text,
            ))
            .unwrap();
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

    #[test]
    fn template_tags_are_plain_text_in_a_placeholder_template() {
        let v = vars(&[("name", "Ada")]);
        assert_eq!(
            merge_keep("{% if x %}{{ name }}{% end %}", &v),
            "{% if x %}Ada{% end %}"
        );
    }

    #[test]
    fn html_output_escapes_values_where_they_land() {
        let v = vars(&[
            ("name", "<b>Tom & 'Jerry'</b>"),
            ("url", "javascript:alert(1)"),
        ]);
        let out = Template::placeholders(r#"<p>{{name}}</p><a href="{{url}}">x</a>"#, |n| {
            v.contains_key(n)
        })
        .render(&RenderContext::new(values(&v), "en", Output::Html))
        .unwrap();
        assert_eq!(
            out,
            r##"<p>&lt;b&gt;Tom &amp; &#39;Jerry&#39;&lt;/b&gt;</p><a href="#">x</a>"##
        );
    }

    #[test]
    fn placeholder_names_lists_accepted_fields_in_order() {
        let t = Template::placeholders("{{a}} {{ b c }} {{b}} {{a}}", |n| !n.contains(' '));
        assert_eq!(t.placeholder_names().collect::<Vec<_>>(), ["a", "b", "a"]);
    }
}

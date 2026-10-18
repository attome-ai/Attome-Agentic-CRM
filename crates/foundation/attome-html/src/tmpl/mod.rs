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
}

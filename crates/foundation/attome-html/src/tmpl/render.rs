//! Rendering a compiled template (Z13-T2), escaping each value for where it
//! lands (Z13-T3) and within bounded time, output and loop work (Z13-T6).

use std::time::{Duration, Instant};

use attome_rules::{Context, Value};

use super::escape::{self, HtmlPlace, Output};
use super::format::{self, Locale};
use super::parse::Node;
use super::{Position, RenderLimit, TemplateError};

/// How much one render may do (Z13-T6); checked between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderLimits {
    pub max_time: Duration,
    pub max_output_bytes: usize,
    /// Loop bodies run, over every loop of the render.
    pub max_iterations: usize,
}

impl Default for RenderLimits {
    fn default() -> Self {
        Self {
            max_time: Duration::from_millis(100),
            max_output_bytes: 1024 * 1024,
            max_iterations: 10_000,
        }
    }
}

/// What a render sees.
#[derive(Debug, Clone)]
pub struct RenderContext {
    /// The values, clock and zone the expressions read.
    pub values: Context,
    /// The language and region (`ar-SA`, `en`); region formatting (Z13-T4)
    /// reads it.
    pub locale: String,
    pub output: Output,
    pub limits: RenderLimits,
}

impl RenderContext {
    pub fn new(values: Context, locale: impl Into<String>, output: Output) -> Self {
        Self {
            values,
            locale: locale.into(),
            output,
            limits: RenderLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: RenderLimits) -> Self {
        self.limits = limits;
        self
    }
}

pub(crate) fn render(nodes: &[Node], ctx: &RenderContext) -> Result<String, TemplateError> {
    let mut renderer = Renderer {
        locale: Locale::parse(&ctx.locale),
        output: ctx.output,
        limits: ctx.limits,
        started: Instant::now(),
        iterations: 0,
        place: HtmlPlace::default(),
        out: String::new(),
        at: Position { line: 1, column: 1 },
    };
    renderer.nodes(nodes, &ctx.values)?;
    Ok(renderer.out)
}

struct Renderer {
    locale: Locale,
    output: Output,
    limits: RenderLimits,
    started: Instant,
    iterations: usize,
    place: HtmlPlace,
    out: String,
    /// The last node with a position, for a limit's error.
    at: Position,
}

impl Renderer {
    fn stop(&self, limit: RenderLimit) -> TemplateError {
        TemplateError::RenderLimit { at: self.at, limit }
    }

    /// The time and output limits, between nodes.
    fn check(&self) -> Result<(), TemplateError> {
        if self.started.elapsed() >= self.limits.max_time {
            return Err(self.stop(RenderLimit::Time));
        }
        if self.out.len() > self.limits.max_output_bytes {
            return Err(self.stop(RenderLimit::Output));
        }
        Ok(())
    }

    fn nodes(&mut self, nodes: &[Node], values: &Context) -> Result<(), TemplateError> {
        for node in nodes {
            self.check()?;
            match node {
                Node::Text(text) => {
                    self.out.push_str(text);
                    if self.output == Output::Html {
                        self.place.advance(text);
                    }
                }
                Node::Output { at, expr, filters } => {
                    self.at = *at;
                    let value = expr
                        .eval(values)
                        .map_err(|error| TemplateError::Expression { at: *at, error })?;
                    let value = if filters.is_empty() {
                        value
                    } else {
                        format::apply(value, filters, &self.locale, values.timezone()).map_err(
                            |message| TemplateError::Expression {
                                at: *at,
                                error: attome_rules::RulesError::Eval(message),
                            },
                        )?
                    };
                    let written = escape::write(&value, self.output, &self.place);
                    self.out.push_str(&written);
                }
                Node::Field(name) => {
                    let value = values.field(name).unwrap_or(&Value::Null);
                    let written = escape::write(value, self.output, &self.place);
                    self.out.push_str(&written);
                }
                Node::Dir { body } => {
                    if self.output == Output::Html {
                        // `lang` is ASCII letters only (`Locale::parse`).
                        let open = if self.locale.is_arabic() {
                            format!("<div dir=\"rtl\" lang=\"{}\">", self.locale.lang())
                        } else {
                            format!("<div dir=\"ltr\" lang=\"{}\">", self.locale.lang())
                        };
                        self.out.push_str(&open);
                        self.place.advance(&open);
                        self.nodes(body, values)?;
                        self.out.push_str("</div>");
                        self.place.advance("</div>");
                    } else {
                        self.nodes(body, values)?;
                    }
                }
                Node::If {
                    at,
                    cond,
                    then,
                    otherwise,
                } => {
                    self.at = *at;
                    let holds = cond
                        .eval(values)
                        .map_err(|error| TemplateError::Expression { at: *at, error })?;
                    let branch = if holds == Value::Bool(true) {
                        then
                    } else {
                        otherwise
                    };
                    self.nodes(branch, values)?;
                }
                Node::For {
                    at,
                    var,
                    list,
                    limit,
                    body,
                } => {
                    self.at = *at;
                    let items = match list
                        .eval(values)
                        .map_err(|error| TemplateError::Expression { at: *at, error })?
                    {
                        Value::List(items) => items,
                        Value::Null => Vec::new(),
                        other => {
                            return Err(TemplateError::Expression {
                                at: *at,
                                error: attome_rules::RulesError::Eval(format!(
                                    "a loop runs over a list, not {}",
                                    other.ty()
                                )),
                            });
                        }
                    };
                    if items.len() > *limit {
                        return Err(TemplateError::LimitExceeded {
                            at: *at,
                            limit: *limit,
                            len: items.len(),
                        });
                    }
                    // One copy of the values per loop: each item replaces the
                    // last one's binding.
                    let mut inner = values.clone();
                    for item in items {
                        self.iterations += 1;
                        if self.iterations > self.limits.max_iterations {
                            return Err(self.stop(RenderLimit::Iterations));
                        }
                        if let Value::Record(fields) = &item {
                            inner =
                                inner.with_related(var.clone(), fields.iter().cloned().collect());
                        }
                        inner = inner.with_field(var.clone(), item);
                        self.nodes(body, &inner)?;
                    }
                }
            }
        }
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use attome_rules::{Schema, Type};
    use chrono::Utc;

    use super::super::{Output, Template, TemplateError};
    use super::*;
    use std::time::Duration;

    fn schema() -> Schema {
        Schema::new()
            .with_field("name", Type::Text)
            .with_field("total", Type::Number)
            .with_related_list(
                "lines",
                vec![
                    ("sku".to_owned(), Type::Text),
                    ("qty".to_owned(), Type::Number),
                ],
            )
    }

    fn values(lines: usize) -> Context {
        let rows = (0..lines)
            .map(|n| {
                vec![
                    ("sku".to_owned(), Value::Text(format!("S-{n}"))),
                    ("qty".to_owned(), Value::Number(n as f64 + 1.0)),
                ]
            })
            .collect();
        Context::new(Utc::now())
            .with_field("name", Value::Text("Salma <Co>".into()))
            .with_field("total", Value::Number(150.0))
            .with_related_list("lines", rows)
    }

    fn render(src: &str, output: Output, lines: usize) -> Result<String, TemplateError> {
        Template::compile(src, &schema())?.render(&RenderContext::new(values(lines), "en", output))
    }

    #[test]
    fn values_render_and_html_is_escaped() {
        assert_eq!(
            render("Dear {{ name }}, you owe {{ total + 1 }}.", Output::Html, 0)
                .unwrap_or_default(),
            "Dear Salma &lt;Co&gt;, you owe 151."
        );
        assert_eq!(
            render("Dear {{ name }}", Output::Text, 0).unwrap_or_default(),
            "Dear Salma <Co>"
        );
    }

    #[test]
    fn conditions_choose_a_branch() {
        let src = "{% if total > 100 %}large{% else %}small{% end %}";
        assert_eq!(render(src, Output::Text, 0).unwrap_or_default(), "large");
        let no_else = "a{% if total < 10 %}b{% end %}c";
        assert_eq!(render(no_else, Output::Text, 0).unwrap_or_default(), "ac");
        let not_bool = Template::compile("{% if total %}x{% end %}", &schema()).unwrap_err();
        assert_eq!(not_bool.code(), "rules.type.mismatch");
    }

    #[test]
    fn loops_repeat_their_body() {
        let src = "{% for line in lines limit 10 %}[{{ line.sku }} x{{ line.qty }}]{% end %}";
        assert_eq!(
            render(src, Output::Text, 3).unwrap_or_default(),
            "[S-0 x1][S-1 x2][S-2 x3]"
        );
        assert_eq!(
            render(src, Output::Text, 0).unwrap_or_default(),
            "",
            "an empty list"
        );
    }

    #[test]
    fn a_loop_over_its_limit_is_an_error() {
        let src = "{% for line in lines limit 2 %}{{ line.sku }}{% end %}";
        let err = render(src, Output::Text, 3).unwrap_err();
        assert_eq!(err.code(), "template.loop.limit_exceeded");
        assert!(matches!(
            err,
            TemplateError::LimitExceeded {
                limit: 2,
                len: 3,
                ..
            }
        ));
        let unbounded =
            Template::compile("{% for line in lines %}x{% end %}", &schema()).unwrap_err();
        assert_eq!(unbounded.code(), "template.syntax");
        let too_big = Template::compile("{% for line in lines limit 5000 %}x{% end %}", &schema())
            .unwrap_err();
        assert_eq!(too_big.code(), "template.syntax");
    }

    #[test]
    fn an_unknown_variable_names_its_place() {
        let err = Template::compile("Hello\n  {{ nickname }}", &schema()).unwrap_err();
        assert_eq!(err.code(), "rules.field.unknown");
        assert_eq!(err.position().line, 2);
        assert_eq!(err.position().column, 3);
        let unclosed = Template::compile("{% if total > 1 %}x", &schema()).unwrap_err();
        assert_eq!(unclosed.code(), "template.syntax");
        let open = Template::compile("{{ name", &schema()).unwrap_err();
        assert_eq!(open.code(), "template.syntax");
        let stray = Template::compile("{% end %}", &schema()).unwrap_err();
        assert_eq!(stray.code(), "template.syntax");
    }

    #[test]
    fn values_escape_for_where_they_land() {
        let src = "<a href=\"{{ name }}\" title=\"{{ name }}\">{{ name }}</a>";
        let out = render(src, Output::Html, 0).unwrap_or_default();
        assert_eq!(
            out,
            "<a href=\"Salma%20%3CCo%3E\" title=\"Salma &lt;Co&gt;\">Salma &lt;Co&gt;</a>"
        );
    }

    fn big_values(lines: usize, sku_len: usize) -> Context {
        let rows = (0..lines)
            .map(|_| {
                vec![
                    ("sku".to_owned(), Value::Text("x".repeat(sku_len))),
                    ("qty".to_owned(), Value::Number(1.0)),
                ]
            })
            .collect();
        values(0).with_related_list("lines", rows)
    }

    #[test]
    fn limits_stop_a_huge_output() {
        let template = Template::compile(
            "{% for line in lines limit 1000 %}{{ line.sku }}{% end %}",
            &schema(),
        )
        .unwrap();
        // Time is not what this test measures.
        let ctx = RenderContext::new(big_values(1000, 2000), "en", Output::Text).with_limits(
            RenderLimits {
                max_time: Duration::from_secs(60),
                ..RenderLimits::default()
            },
        );
        let err = template.render(&ctx).unwrap_err();
        assert_eq!(err.code(), "template.limit.output");
    }

    #[test]
    fn limits_stop_too_many_iterations() {
        let template = Template::compile(
            "{% for a in lines limit 1000 %}{% for b in lines limit 1000 %}.{% end %}{% end %}",
            &schema(),
        )
        .unwrap();
        let ctx =
            RenderContext::new(big_values(200, 1), "en", Output::Text).with_limits(RenderLimits {
                max_time: Duration::from_secs(60),
                ..RenderLimits::default()
            });
        let err = template.render(&ctx).unwrap_err();
        assert_eq!(err.code(), "template.limit.iterations");
    }

    #[test]
    fn limits_stop_a_slow_render() {
        let template = Template::compile("{{ name }}", &schema()).unwrap();
        let ctx = RenderContext::new(values(0), "en", Output::Text).with_limits(RenderLimits {
            max_time: Duration::ZERO,
            ..RenderLimits::default()
        });
        let err = template.render(&ctx).unwrap_err();
        assert_eq!(err.code(), "template.limit.time");
    }

    #[test]
    fn format_filters_in_a_template_per_locale() {
        let template = Template::compile(
            "{% dir %}{{ name }}: {{ total | currency('SAR') }}{% end %}",
            &schema(),
        )
        .unwrap();
        let en = template
            .render(&RenderContext::new(values(0), "en", Output::Html))
            .unwrap();
        assert_eq!(
            en,
            "<div dir=\"ltr\" lang=\"en\">Salma &lt;Co&gt;: SAR 150.00</div>"
        );
        let ar = template
            .render(&RenderContext::new(values(0), "ar-SA", Output::Html))
            .unwrap();
        assert_eq!(
            ar,
            "<div dir=\"rtl\" lang=\"ar\">Salma &lt;Co&gt;: ١٥٠٫٠٠ ر.س</div>"
        );
        let text = template
            .render(&RenderContext::new(values(0), "ar", Output::Text))
            .unwrap();
        assert_eq!(text, "Salma <Co>: ١٥٠٫٠٠ ر.س");
    }

    #[test]
    fn format_filter_errors_at_compile() {
        let code = |src: &str| Template::compile(src, &schema()).unwrap_err().code();
        assert_eq!(code("{{ name | number(2) }}"), "rules.type.mismatch");
        assert_eq!(code("{{ total | upper }}"), "template.syntax");
        assert_eq!(code("{{ total | }}"), "template.syntax");
        assert_eq!(code("{% dir %}x"), "template.syntax");
    }
}

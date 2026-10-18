//! Rendering a compiled template (Z13-T2).

use attome_rules::{Context, Value};

use super::TemplateError;
use super::escape::{self, Output};
use super::parse::Node;

/// What a render sees.
#[derive(Debug, Clone)]
pub struct RenderContext {
    /// The values, clock and zone the expressions read.
    pub values: Context,
    /// The language and region (`ar-SA`, `en`); region formatting (Z13-T4)
    /// reads it.
    pub locale: String,
    pub output: Output,
}

impl RenderContext {
    pub fn new(values: Context, locale: impl Into<String>, output: Output) -> Self {
        Self {
            values,
            locale: locale.into(),
            output,
        }
    }
}

pub(crate) fn render(nodes: &[Node], ctx: &RenderContext) -> Result<String, TemplateError> {
    let mut out = String::new();
    render_into(nodes, &ctx.values, ctx.output, &mut out)?;
    Ok(out)
}

fn render_into(
    nodes: &[Node],
    values: &Context,
    output: Output,
    out: &mut String,
) -> Result<(), TemplateError> {
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Output { at, expr } => {
                let value = expr
                    .eval(values)
                    .map_err(|error| TemplateError::Expression { at: *at, error })?;
                out.push_str(&escape::write(&value, output));
            }
            Node::If {
                at,
                cond,
                then,
                otherwise,
            } => {
                let holds = cond
                    .eval(values)
                    .map_err(|error| TemplateError::Expression { at: *at, error })?;
                let branch = if holds == Value::Bool(true) {
                    then
                } else {
                    otherwise
                };
                render_into(branch, values, output, out)?;
            }
            Node::For {
                at,
                var,
                list,
                limit,
                body,
            } => {
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
                for item in items {
                    let mut inner = values.clone();
                    if let Value::Record(fields) = &item {
                        inner = inner.with_related(var.clone(), fields.iter().cloned().collect());
                    }
                    let inner = inner.with_field(var.clone(), item);
                    render_into(body, &inner, output, out)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use attome_rules::{Schema, Type};
    use chrono::Utc;

    use super::super::{Output, Template, TemplateError};
    use super::*;

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
}

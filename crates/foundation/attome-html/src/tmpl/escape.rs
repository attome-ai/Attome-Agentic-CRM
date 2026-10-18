//! How a value is written into the output (Z13-T2; Z13-T3 adds the
//! attribute and URL contexts, Z13-T4 region formatting).

use attome_rules::Value;

/// What a template renders to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// Every value HTML-escaped.
    Html,
    /// Every value as is (a plain-text email, an SMS).
    Text,
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

/// A value written for `output`.
pub(crate) fn write(value: &Value, output: Output) -> String {
    let text = display(value);
    match output {
        Output::Html => crate::escape_html(&text),
        Output::Text => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            write(&Value::Text("<b>&</b>".into()), Output::Html),
            "&lt;b&gt;&amp;&lt;/b&gt;"
        );
        assert_eq!(write(&Value::Text("<b>".into()), Output::Text), "<b>");
    }
}

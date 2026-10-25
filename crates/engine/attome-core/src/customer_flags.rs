//! T6-T2: customer flags, which rules and flows read as `flag('name')`.
//!
//! The source of truth is `customer_flag`, read on each use with no cache,
//! so a change (an emergency off above all) holds on every node at once. A
//! flag is on when its value is on and it is not switched off in an
//! emergency; a name with no row is off.

use std::collections::HashMap;

use attome_db::DbPool;
use attome_types::AppError;

/// Whether `src` calls `flag(`, outside quotes. Pure.
pub fn references(src: &str) -> bool {
    let mut quote: Option<char> = None;
    let chars: Vec<char> = src.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if chars[i..].starts_with(&['f', 'l', 'a', 'g'])
            && (i == 0 || !(chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_'))
        {
            let rest = chars[i + 4..].iter().find(|c| !c.is_whitespace());
            if rest == Some(&'(') {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Every flag and whether it is on now.
pub async fn load(db: &DbPool) -> Result<HashMap<String, bool>, AppError> {
    let rows: Vec<(String, bool)> =
        sqlx::query_as("SELECT name, value AND NOT emergency_off FROM customer_flag")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    Ok(rows.into_iter().collect())
}

/// Whether `name` is a valid flag name: lower-case letters, digits and
/// underscores, starting with a letter, at most 63 characters. Pure.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 63
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_function_references_skip_quotes_and_longer_names() {
        assert!(references("flag('beta') && amount > 5"));
        assert!(references("flag ('beta')"));
        assert!(!references("myflag('x')"));
        assert!(!references("name == 'flag(x)'"));
        assert!(!references("flags > 1"));
    }

    #[test]
    fn flag_function_names_are_checked() {
        assert!(valid_name("new_checkout"));
        assert!(!valid_name("New"));
        assert!(!valid_name("1x"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(64)));
    }
}

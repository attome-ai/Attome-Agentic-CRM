//! Z2-T8: query tags. A query's text starts with a `/* class */` comment
//! naming the engine and operation that sent it (`entity.merge`,
//! `query.execute`, `jobs.queue`), so `pg_stat_statements`, the slow-query
//! log and `pg_stat_activity` show where a statement came from. The class is
//! a `&'static str` written in the code, never request data.
//!
//! PostgreSQL keeps the leading comment in the statement text it reports
//! (`pg_stat_statements` computes the query id without it, so a tag never
//! splits one statement's statistics).

/// A string literal with its class comment, at compile time:
/// `sqlx::query(attome_db::tagged_sql!("entity.tags", "SELECT ..."))`.
#[macro_export]
macro_rules! tagged_sql {
    ($class:literal, $sql:literal) => {
        concat!("/* ", $class, " */ ", $sql)
    };
}

/// [`tagged_sql!`] for SQL a builder made at run time.
pub fn tag_dynamic(class: &'static str, sql: &str) -> String {
    debug_assert!(
        !class.contains("*/") && !class.contains("/*"),
        "a query tag may not open or close a comment: {class}"
    );
    format!("/* {class} */ {sql}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_sql_prefixes_comment() {
        assert_eq!(
            tagged_sql!("entity.get", "SELECT 1"),
            "/* entity.get */ SELECT 1"
        );
        assert_eq!(
            tag_dynamic("query.execute", "SELECT 2"),
            "/* query.execute */ SELECT 2"
        );
    }

    #[test]
    #[should_panic(expected = "may not open or close a comment")]
    #[cfg(debug_assertions)]
    fn tag_dynamic_rejects_comment_terminator() {
        let _ = tag_dynamic("evil */ DROP", "SELECT 1");
    }
}

use attome_config::AppConfig;
use sqlx::PgPool;

use crate::ident::MAX_IDENTIFIER_LEN;

/// Identifiers can't be bind parameters, so the configured schema name is
/// validated before being spliced into DDL — the same validator and 48-byte
/// cap `xrm-entity::provision` uses for entity/attribute logicalnames
/// (`crate::ident`, CLEANUP-REVIEW 3.4). A schema name gets no derived names,
/// so 48 rather than 63 is only for one shared cap.
fn valid_identifier(s: &str) -> bool {
    crate::ident::valid_identifier(s, MAX_IDENTIFIER_LEN)
}

/// Creates `config.database.schema` if it doesn't exist yet. Must run before
/// any migration: `AppConfig::database_url` puts this schema on the
/// connection's `search_path`, and on a genuinely fresh database Postgres
/// refuses any unqualified `CREATE TABLE` with "no schema has been selected
/// to create in" until the schema exists — `CREATE TABLE IF NOT EXISTS`
/// inside a migration file does not help, since the schema itself, not a
/// table, is what's missing.
pub async fn ensure_schema(pool: &PgPool, config: &AppConfig) -> Result<(), sqlx::Error> {
    let schema = &config.database.schema;
    if !valid_identifier(schema) {
        return Err(sqlx::Error::Configuration(
            format!("invalid database.schema value: {schema:?}").into(),
        ));
    }

    // BDB-F5 — `IF NOT EXISTS` is a check-then-create, so two sessions racing
    // the same *first* boot (a multi-node deploy, a `migrate` job starting
    // beside a booting node) can both pass the existence check; the loser gets
    // `42P06` (`duplicate_schema`) or `23505` on `pg_namespace`'s unique
    // index. The schema exists either way. Re-check and accept it instead of
    // refusing to boot on a benign duplicate. Deliberately no advisory lock:
    // tolerating the duplicate is simpler and leaves D-351's registry
    // untouched (plan §7, rejected alternatives).
    match sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS \"{schema}\""))
        .execute(pool)
        .await
    {
        Ok(_) => Ok(()),
        Err(error) if is_concurrent_schema_creation(&error) => {
            if schema_exists(pool, schema).await? {
                Ok(())
            } else {
                // Not the benign race after all (a 23505 from something else,
                // a permissions surprise): surface the original error.
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

/// `42P06` (duplicate_schema) or `23505` on `pg_namespace`'s unique index —
/// the two ways the loser of a concurrent `CREATE SCHEMA IF NOT EXISTS`
/// reports that the winner already created the schema.
fn is_concurrent_schema_creation(error: &sqlx::Error) -> bool {
    matches!(crate::sqlstate(error).as_deref(), Some("42P06" | "23505"))
}

async fn schema_exists(pool: &PgPool, schema: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)")
        .bind(schema)
        .fetch_one(pool)
        .await
}

// P-provisioning-hardening item (a) — D-101.
#[cfg(test)]
mod tests {
    use super::{MAX_IDENTIFIER_LEN, valid_identifier};

    #[test]
    fn accepts_identifier_at_cap() {
        let name: String = "a".repeat(MAX_IDENTIFIER_LEN);
        assert!(valid_identifier(&name));
    }

    #[test]
    fn rejects_identifier_over_cap() {
        let name: String = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(!valid_identifier(&name));
    }

    /// CLEANUP-REVIEW 3.4: the accept/reject set is unchanged by the move to
    /// `crate::ident` — leading underscore allowed, lowercase ASCII only.
    #[test]
    fn charset_accept_reject_set() {
        for ok in ["attome_dev", "_private", "_", "s1", "a_b_9"] {
            assert!(valid_identifier(ok), "{ok}");
        }
        for bad in ["", "Attome", "1abc", "a-b", "a b", "a.b", "a\"b", "é"] {
            assert!(!valid_identifier(bad), "{bad:?}");
        }
    }
}

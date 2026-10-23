//! L1-T2: a master entity's side tables, provisioned when the entity
//! becomes master (`attome_compliance::governance_admin::set_entity_master_data`).
//!
//! - `<entity>__contribution`: what each source system sent for a golden
//!   record. One row per (source system, external id); `golden_id` is the
//!   record it is attached to (none while held), with its payload, when it
//!   was received, and its status (`attached`, `held`, `detached`) and why
//!   it is held.
//! - `<entity>__provenance`: for each golden record and attribute, the
//!   contribution its value came from, by which survivorship rule, when,
//!   and who pinned it, if a person did.
//!
//! One pair per master entity, never one shared table (design). Both are
//! created with `CREATE TABLE IF NOT EXISTS` under the provisioning
//! `lock_timeout` (`exec_ddl_locked`), so making an entity master again
//! changes nothing. The names are composed from a validated entity name and
//! quoted; the read-only role may read them, as it may every provisioned
//! table.

use attome_db::DbPool;
use attome_types::AppError;

use super::ddl::exec_ddl_locked;
use super::identifiers::{attribute_index_name, valid_identifier};

/// The contribution table of `entity`.
pub fn contribution_table(entity: &str) -> String {
    format!("{entity}__contribution")
}

/// The provenance table of `entity`.
pub fn provenance_table(entity: &str) -> String {
    format!("{entity}__provenance")
}

/// The two side tables' DDL, in order.
pub fn master_table_ddl(entity: &str) -> Result<Vec<String>, AppError> {
    if !valid_identifier(entity) {
        return Err(AppError::internal(format!(
            "invalid master entity identifier: {entity}"
        )));
    }
    let contribution = contribution_table(entity);
    let provenance = provenance_table(entity);
    if contribution.len() > 63 || provenance.len() > 63 {
        return Err(AppError::Validation(format!(
            "the entity name {entity:?} is too long for its master-data side tables"
        )));
    }
    let q = attome_core::quote_ident;
    let (entity_t, contribution_t, provenance_t) = (q(entity), q(&contribution), q(&provenance));
    Ok(vec![
        format!(
            "CREATE TABLE IF NOT EXISTS {contribution_t} (
                 id uuid PRIMARY KEY DEFAULT uuidv7(),
                 golden_id uuid REFERENCES {entity_t} (id) ON DELETE SET NULL,
                 source_system text NOT NULL,
                 external_id text NOT NULL,
                 received_at timestamptz NOT NULL DEFAULT now(),
                 payload jsonb NOT NULL DEFAULT '{{}}',
                 status text NOT NULL DEFAULT 'held'
                     CHECK (status IN ('attached', 'held', 'detached')),
                 held_reason text,
                 UNIQUE (source_system, external_id)
             )"
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS {} ON {contribution_t} (golden_id)",
            q(&attribute_index_name(&contribution, "golden_id")?)
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {provenance_t} (
                 golden_id uuid NOT NULL REFERENCES {entity_t} (id) ON DELETE CASCADE,
                 attribute text NOT NULL,
                 contribution_id uuid REFERENCES {contribution_t} (id) ON DELETE SET NULL,
                 rule text NOT NULL,
                 chosen_at timestamptz NOT NULL DEFAULT now(),
                 pinned_by uuid,
                 PRIMARY KEY (golden_id, attribute)
             )"
        ),
    ])
}

/// Creates `entity`'s contribution and provenance tables when they do not
/// exist yet.
pub async fn ensure_master_tables(db: &DbPool, entity: &str) -> Result<(), AppError> {
    for sql in master_table_ddl(entity)? {
        exec_ddl_locked(db, &[], &sql).await.map_err(|e| {
            tracing::error!(error = %e, entity = %entity, "master-data side table DDL failed");
            AppError::internal(e)
        })?;
    }
    // The read-only role reads them, as it does every provisioned table.
    let grant = format!(
        "GRANT SELECT ON {}, {} TO attome_readonly",
        attome_core::quote_ident(&contribution_table(entity)),
        attome_core::quote_ident(&provenance_table(entity))
    );
    exec_ddl_locked(db, &[], &grant).await.map_err(|e| {
        tracing::error!(error = %e, entity = %entity, "master-data side table grant failed");
        AppError::internal(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_tables_are_per_entity_and_quoted() {
        let ddl = master_table_ddl("customer").unwrap();
        assert_eq!(ddl.len(), 3);
        assert!(ddl.iter().all(|s| !s.contains("Bad")));
        assert!(ddl[0].starts_with("CREATE TABLE IF NOT EXISTS \"customer__contribution\""));
        assert!(ddl[0].contains("REFERENCES \"customer\" (id)"));
        assert!(ddl[0].contains("UNIQUE (source_system, external_id)"));
        assert!(ddl[2].contains("PRIMARY KEY (golden_id, attribute)"));
        assert!(master_table_ddl("Bad Name").is_err());
        assert!(
            master_table_ddl(&"x".repeat(50)).is_err(),
            "too long with the suffix"
        );
    }
}

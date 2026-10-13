//! Source-scan backfill (TODO-014, closes gap G4).
//!
//! **Why this exists at all.** The change feed holds only events emitted since
//! migration `0091` shipped. "A full rebuild is just resetting the cursor"
//! sounds right and indexes *nothing* — every record the customer had before
//! the outbox existed, which on a real deployment is all of them. Without this
//! module Stage 1 ships a search engine that finds only records touched after
//! go-live, and it does so silently: the queries work, the index is healthy,
//! the results are simply missing most of the data.
//!
//! **Load first, index after.** Upserting a million rows through four GIN
//! indexes is roughly an order of magnitude slower than loading them into an
//! unindexed table and building the indexes once at the end — GIN pays its
//! cost per insert, and building from a complete table lets it sort. So the
//! sequence is: stage → load → index → swap.
//!
//! ## The part that is easy to get wrong
//!
//! A backfill takes minutes to hours. Records change during it. If the cursor
//! were advanced to "now" at the end, every one of those changes would be lost
//! — the scan captured a value, the record changed after the scan passed it,
//! and the event that would have fixed it was skipped as already-consumed.
//!
//! So [`Backfill::start`] records the cursor position **before** the scan
//! begins, and [`Backfill::finish`] rewinds the drain's cursor to that mark.
//! The drain then replays every event from before the scan started. Some of
//! that work is redundant — and it is free, because the `content_hash` gate
//! (TODO-016) skips the write for anything the scan already got right.

use attome_types::AppError;
use sqlx::PgPool;
use uuid::Uuid;

use crate::drain::CONSUMER;
use crate::project::ProjectedRow;

/// Rows loaded per batch.
///
/// Bounded for the reason D-358 documents: one enormous transaction holds the
/// change feed's visibility horizon down for *every* consumer, so a backfill
/// that ran as a single statement would stall the drain it is trying to help.
pub const BATCH_SIZE: i64 = 5_000;

// Compile-time, not a test: the bound is a property of the constant, and a
// value large enough to run for minutes stalls every OTHER consumer of the
// change feed by holding the visibility horizon down (D-358). Catching that at
// build time rather than in a test run is strictly better.
const _: () = assert!(BATCH_SIZE > 0);
const _: () = assert!(BATCH_SIZE <= 10_000);

/// The staging table's name. Fixed rather than randomised so an interrupted
/// backfill leaves an obvious artifact an operator can find and drop, instead
/// of an accumulating pile of differently-suffixed tables nobody recognises.
const STAGING_TABLE: &str = "search_index_staging";

/// A backfill in progress.
pub struct Backfill {
    /// The drain cursor's position when the scan started. The whole
    /// correctness argument of this module — see the module doc.
    cursor_mark: i64,
    pub loaded: u64,
}

impl std::fmt::Debug for Backfill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backfill").finish_non_exhaustive()
    }
}

impl Backfill {
    /// Creates the staging table and records where the change feed stood.
    ///
    /// The staging table is deliberately **unlogged**: it is rebuilt from
    /// source data on any failure, so paying WAL for it buys nothing. That
    /// also means it does not survive a crash, which is correct — a
    /// half-loaded staging table must never be swapped in.
    pub async fn start(db: &PgPool) -> Result<Self, AppError> {
        // Read the cursor BEFORE the scan. Order matters: reading it after
        // would leave a window whose events are neither scanned nor replayed.
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let position = attome_core::change_feed::cursor(&mut conn, CONSUMER).await?;
        drop(conn);

        sqlx::query(&format!("DROP TABLE IF EXISTS {STAGING_TABLE}"))
            .execute(db)
            .await
            .map_err(AppError::internal)?;

        // `INCLUDING DEFAULTS` but NOT `INCLUDING INDEXES` — building the
        // indexes now is precisely what this module exists to avoid.
        sqlx::query(&format!(
            "CREATE UNLOGGED TABLE {STAGING_TABLE} \
             (LIKE search_index INCLUDING DEFAULTS)"
        ))
        .execute(db)
        .await
        .map_err(AppError::internal)?;

        Ok(Self {
            cursor_mark: position.last_commit_xid,
            loaded: 0,
        })
    }

    /// Loads one batch of projected rows into staging.
    ///
    /// A multi-row `INSERT ... SELECT UNNEST`, not a row-at-a-time loop: at
    /// `BATCH_SIZE` rows the round-trip cost dominates everything else.
    pub async fn load_batch(
        &mut self,
        db: &PgPool,
        entity_logicalname: &str,
        rows: &[(Uuid, ProjectedRow, Option<Uuid>, Option<Uuid>)],
    ) -> Result<(), AppError> {
        if rows.is_empty() {
            return Ok(());
        }

        let record_ids: Vec<Uuid> = rows.iter().map(|(id, ..)| *id).collect();
        let titles: Vec<String> = rows.iter().map(|(_, r, ..)| r.title.clone()).collect();
        let title_norms: Vec<String> = rows.iter().map(|(_, r, ..)| r.title_norm.clone()).collect();
        let subtitles: Vec<Option<String>> =
            rows.iter().map(|(_, r, ..)| r.subtitle.clone()).collect();
        let bodies: Vec<String> = rows
            .iter()
            .map(|(_, r, ..)| r.body_display.clone())
            .collect();
        let indexed: Vec<String> = rows
            .iter()
            .map(|(_, r, ..)| r.body_indexed.clone())
            .collect();
        let hashes: Vec<Vec<u8>> = rows
            .iter()
            .map(|(_, r, ..)| r.content_hash.clone())
            .collect();
        let orgs: Vec<Option<Uuid>> = rows.iter().map(|(_, _, o, _)| *o).collect();
        let owners: Vec<Option<Uuid>> = rows.iter().map(|(_, _, _, o)| *o).collect();

        // `exact_keys` is an array per row, so it cannot ride in a flat
        // `UNNEST` alongside the scalars. Passed as a JSONB array of arrays and
        // reassembled — the alternative is a second statement per batch, which
        // is worse than one JSON parse.
        let exact_keys = serde_json::to_value(
            rows.iter()
                .map(|(_, r, ..)| r.exact_keys.clone())
                .collect::<Vec<_>>(),
        )
        .map_err(|e| AppError::internal(format!("exact_keys serialization failed: {e}")))?;

        sqlx::query(&format!(
            "INSERT INTO {STAGING_TABLE} \
                (corpus, entity_logicalname, record_id, title, title_norm, subtitle, \
                 body_display, body_indexed, exact_keys, tsv, organization_ref, \
                 owner_id, indexed_at, content_hash) \
             SELECT 'record', $1, u.record_id, u.title, u.title_norm, u.subtitle, \
                    u.body_display, u.body_indexed, \
                    ARRAY(SELECT jsonb_array_elements_text($10::jsonb -> (u.ord - 1)::int)), \
                    to_tsvector('attome_search', coalesce(u.title_norm, '') || ' ' || coalesce(u.body_indexed, '')), \
                    u.organization_ref, u.owner_id, NOW(), u.content_hash \
             FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::text[], \
                         $7::text[], $8::uuid[], $9::uuid[], $11::bytea[]) \
                  WITH ORDINALITY AS u(record_id, title, title_norm, subtitle, body_display, \
                                       body_indexed, organization_ref, owner_id, content_hash, ord)"
        ))
        .bind(entity_logicalname)
        .bind(&record_ids)
        .bind(&titles)
        .bind(&title_norms)
        .bind(&subtitles)
        .bind(&bodies)
        .bind(&indexed)
        .bind(&orgs)
        .bind(&owners)
        .bind(&exact_keys)
        .bind(&hashes)
        .execute(db)
        .await
        .map_err(AppError::internal)?;

        self.loaded += rows.len() as u64;
        Ok(())
    }

    /// Builds the indexes, swaps staging in, and rewinds the drain cursor.
    ///
    /// The swap takes ACCESS EXCLUSIVE on both tables, but only for the
    /// rename — a catalog change, not a scan. Search is unavailable for that
    /// instant rather than for the hours the load took, which is the entire
    /// reason for staging rather than upserting in place.
    pub async fn finish(self, db: &PgPool) -> Result<u64, AppError> {
        // Indexes first, on the complete table, where the build can sort
        // rather than pay GIN's per-insert cost.
        for ddl in [
            format!("CREATE INDEX ON {STAGING_TABLE} USING gin (tsv) WITH (fastupdate = off)"),
            format!("CREATE INDEX ON {STAGING_TABLE} (title_norm text_pattern_ops)"),
            format!(
                "CREATE INDEX ON {STAGING_TABLE} USING gin (title_norm gin_trgm_ops) WITH (fastupdate = off)"
            ),
            format!(
                "CREATE INDEX ON {STAGING_TABLE} USING gin (exact_keys) WITH (fastupdate = off)"
            ),
            format!("CREATE INDEX ON {STAGING_TABLE} (organization_ref)"),
            format!("CREATE INDEX ON {STAGING_TABLE} (entity_logicalname, source_modifiedon DESC)"),
            format!(
                "ALTER TABLE {STAGING_TABLE} ADD PRIMARY KEY (corpus, entity_logicalname, record_id)"
            ),
        ] {
            sqlx::query(&ddl)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
        }

        // A staging table built UNLOGGED must become LOGGED before it is the
        // live index — otherwise the first crash empties the platform's search
        // silently, and the symptom is "search returns nothing" with a
        // perfectly healthy-looking table.
        sqlx::query(&format!("ALTER TABLE {STAGING_TABLE} SET LOGGED"))
            .execute(db)
            .await
            .map_err(AppError::internal)?;

        let mut tx = attome_db::tx::begin(db).await?;
        sqlx::query("DROP TABLE IF EXISTS search_index_old")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query("ALTER TABLE search_index RENAME TO search_index_old")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        sqlx::query(&format!(
            "ALTER TABLE {STAGING_TABLE} RENAME TO search_index"
        ))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        tx.commit().await.map_err(AppError::internal)?;

        sqlx::query("DROP TABLE IF EXISTS search_index_old")
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        sqlx::query("GRANT SELECT, INSERT, UPDATE, DELETE ON search_index TO attome_runtime")
            .execute(db)
            .await
            .map_err(AppError::internal)?;

        // **Rewind, do not advance.** Every record that changed during the
        // scan gets its event replayed. Redundant for anything the scan
        // already captured correctly, and free — the content_hash gate skips
        // those writes entirely (TODO-016).
        self.rewind_cursor(db).await?;

        Ok(self.loaded)
    }

    async fn rewind_cursor(&self, db: &PgPool) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE change_consumer_cursor \
                SET last_commit_xid = $2::text::xid8, last_id = NULL, updated_at = NOW() \
              WHERE consumer = $1",
        )
        .bind(CONSUMER)
        .bind(self.cursor_mark.to_string())
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        Ok(())
    }

    /// Where the cursor will be rewound to. Exposed for the test that proves
    /// the mark is taken before the scan rather than after.
    pub fn cursor_mark(&self) -> i64 {
        self.cursor_mark
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The staging table name is fixed, so an interrupted backfill leaves one
    /// findable artifact rather than an accumulating pile of randomly-suffixed
    /// tables nobody recognises.
    #[test]
    fn the_staging_table_name_is_stable() {
        assert_eq!(STAGING_TABLE, "search_index_staging");
    }
}

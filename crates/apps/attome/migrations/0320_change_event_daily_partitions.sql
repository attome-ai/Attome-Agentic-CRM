-- Y7-T3: the change-event outbox is partitioned by day on created_at, so
-- retention drops whole days (`attome_core::change_feed::partitions`)
-- instead of deleting row by row. One partition per day from the oldest row
-- to three days ahead, plus a default partition for a row outside every
-- range; the daily prune job creates the days ahead from then on.
--
-- The primary key becomes (id, created_at): a partitioned table's unique
-- keys must contain the partition key. change_consumer_applied's foreign
-- key to entity_change_event(id) cannot survive that, so it is dropped; the
-- prune deletes a consumer's applied rows itself once their event is gone.
--
-- Short lock: the new table is filled and indexed while writers carry on
-- (the copy holds only ACCESS SHARE on the old one). Only then is the old
-- table locked, the rows committed since the copy's snapshot are added, and
-- the names are swapped. The lock is waited for at most 5 seconds, so a busy
-- table fails the migration rather than wedging writers behind it.
-- Idempotent: a table that is already partitioned is left alone.
DO $$
DECLARE
    first_day date;
    last_day date := (now() AT TIME ZONE 'UTC')::date + 3;
    d date;
    part text;
    copied_before xid8;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema()
          AND c.relname = 'entity_change_event'
          AND c.relkind = 'p'
    ) THEN
        RETURN;
    END IF;

    SET LOCAL lock_timeout = '5s';

    CREATE TABLE entity_change_event_new (
        LIKE entity_change_event INCLUDING DEFAULTS INCLUDING CONSTRAINTS
    ) PARTITION BY RANGE (created_at);
    ALTER TABLE entity_change_event_new OWNER TO attome_migrator;
    CREATE TABLE entity_change_event_default PARTITION OF entity_change_event_new DEFAULT;
    ALTER TABLE entity_change_event_default OWNER TO attome_migrator;

    SELECT COALESCE(
               min((created_at AT TIME ZONE 'UTC')::date),
               (now() AT TIME ZONE 'UTC')::date
           )
      INTO first_day
      FROM entity_change_event;
    d := first_day;
    WHILE d <= last_day LOOP
        part := 'entity_change_event_d' || to_char(d, 'YYYYMMDD');
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF entity_change_event_new FOR VALUES FROM (%L) TO (%L)',
            part,
            to_char(d, 'YYYY-MM-DD') || ' 00:00:00+00',
            to_char(d + 1, 'YYYY-MM-DD') || ' 00:00:00+00'
        );
        EXECUTE format('ALTER TABLE %I OWNER TO attome_migrator', part);
        d := d + 1;
    END LOOP;

    -- Every write whose transaction began before this point is visible to
    -- the copy below; a later one may not be, and is added under the lock.
    copied_before := pg_snapshot_xmin(pg_current_snapshot());
    INSERT INTO entity_change_event_new SELECT * FROM entity_change_event;

    ALTER TABLE entity_change_event_new
        ADD CONSTRAINT entity_change_event_new_pkey PRIMARY KEY (id, created_at);
    CREATE INDEX entity_change_event_new_feed_idx
        ON entity_change_event_new (commit_xid, id);
    CREATE INDEX entity_change_event_new_pending_idx
        ON entity_change_event_new (created_at) WHERE processed_at IS NULL;
    CREATE INDEX entity_change_event_new_record_version_idx
        ON entity_change_event_new (entity_logicalname, record_id, row_version)
        WHERE row_version IS NOT NULL;
    CREATE INDEX entity_change_event_new_seq_idx ON entity_change_event_new (seq);

    LOCK TABLE entity_change_event IN ACCESS EXCLUSIVE MODE;
    INSERT INTO entity_change_event_new
    SELECT o.* FROM entity_change_event o
     WHERE o.commit_xid >= copied_before
       AND NOT EXISTS (
           SELECT 1 FROM entity_change_event_new n
            WHERE n.id = o.id AND n.created_at = o.created_at
       );

    ALTER TABLE change_consumer_applied
        DROP CONSTRAINT IF EXISTS change_consumer_applied_event_id_fkey;
    DROP TABLE entity_change_event;
    ALTER TABLE entity_change_event_new RENAME TO entity_change_event;
    ALTER INDEX entity_change_event_new_pkey RENAME TO entity_change_event_pkey;
    ALTER INDEX entity_change_event_new_feed_idx RENAME TO core_entity_change_event_feed_idx;
    ALTER INDEX entity_change_event_new_pending_idx
        RENAME TO core_entity_change_event_pending_idx;
    ALTER INDEX entity_change_event_new_record_version_idx
        RENAME TO entity_change_event_record_version_idx;
    ALTER INDEX entity_change_event_new_seq_idx RENAME TO entity_change_event_seq_idx;

    GRANT SELECT, INSERT, UPDATE, DELETE ON entity_change_event TO attome_runtime;
END $$;

-- P-db-maintenance step 1 — bloat/autovacuum measurement harness.
--
-- Mirrors attome-metadata::provision's generic entity shape (id/created_at/
-- row_version, one non-PK index) so the measured behavior maps to what
-- provision_table actually emits, not an idealized synthetic shape. Four
-- tables: {mutable,append}_{stock,tuned} — "stock" carries no WITH() clause
-- (today's un-tuned reloptions before P-db-maintenance item (a) shipped),
-- "tuned" carries the exact MUTABLE_STORAGE_PARAMS/APPEND_ONLY_STORAGE_PARAMS
-- strings from crates/engine/attome-metadata/src/provision.rs — keep these two
-- literals byte-identical to that file's constants, or the comparison stops
-- meaning what this doc claims it means.
--
-- seq_id (plain BIGINT) exists only so pgbench can address rows with
-- `random(1, :maxseq)` — id (UUID) stays the realistic PK/identity column,
-- payload approximates a real record's row width so fillfactor has
-- something to matter for.

-- Defensive: migration 0018_role_statement_timeout.sql (P1.12) sets a
-- role-level `statement_timeout = 500ms` on whatever role connects as
-- CURRENT_USER (guidelines §14.1's fast-read class default) -- correct and
-- intentional for ordinary app traffic, but it silently killed both the
-- bulk seed INSERT and every pgbench transaction the first time this
-- harness ran against a `postgres` role that had those migrations applied
-- (same "role-level session state, not request-scoped" class of gotcha as
-- guidelines' `SET LOCAL` note on pool.rs's `connect_options`). This DB is
-- throwaway and single-role, so resetting unconditionally is safe --
-- exactly the kind of long-running bulk workload pool.rs's own comment
-- says should raise its timeout per-transaction rather than live under the
-- 500ms default.
ALTER ROLE postgres RESET statement_timeout;

DROP SCHEMA IF EXISTS bloat_test CASCADE;
CREATE SCHEMA bloat_test;

CREATE TABLE bloat_test.mutable_stock (
    seq_id           BIGINT PRIMARY KEY,
    id               UUID DEFAULT uuidv7(),
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    modified_at       TIMESTAMPTZ,
    organization_ref UUID,
    is_active        BOOLEAN DEFAULT TRUE,
    row_version      BIGINT NOT NULL DEFAULT 0,
    payload          TEXT
);
CREATE INDEX ON bloat_test.mutable_stock (organization_ref);

CREATE TABLE bloat_test.mutable_tuned (
    LIKE bloat_test.mutable_stock INCLUDING ALL
) WITH (fillfactor = 90, autovacuum_vacuum_scale_factor = 0.02, autovacuum_vacuum_cost_delay = 2);

CREATE TABLE bloat_test.append_stock (
    seq_id           BIGINT PRIMARY KEY,
    id               UUID DEFAULT uuidv7(),
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    organization_ref UUID,
    payload          TEXT
);
CREATE INDEX ON bloat_test.append_stock (organization_ref);
CREATE INDEX ON bloat_test.append_stock (created_at);
CREATE SEQUENCE bloat_test.append_stock_seq OWNED BY bloat_test.append_stock.seq_id;

CREATE TABLE bloat_test.append_tuned (
    LIKE bloat_test.append_stock INCLUDING ALL
) WITH (fillfactor = 100, autovacuum_vacuum_insert_scale_factor = 0.02, autovacuum_vacuum_scale_factor = 0.05, autovacuum_vacuum_cost_delay = 2);
CREATE SEQUENCE bloat_test.append_tuned_seq OWNED BY bloat_test.append_tuned.seq_id;

-- Seed: mutable tables get :rowcount rows up front (churn is all UPDATE, no
-- growth); append tables start EMPTY (their own INSERT script is the sole
-- source of rows) but need a live sequence to hand out seq_id from 1.
INSERT INTO bloat_test.mutable_stock (seq_id, organization_ref, payload)
SELECT g, uuidv7(), repeat('x', 200) FROM generate_series(1, :rowcount) g;

INSERT INTO bloat_test.mutable_tuned (seq_id, organization_ref, payload)
SELECT g, uuidv7(), repeat('x', 200) FROM generate_series(1, :rowcount) g;

ANALYZE bloat_test.mutable_stock;
ANALYZE bloat_test.mutable_tuned;

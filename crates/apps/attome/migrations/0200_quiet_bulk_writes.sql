-- B5-T3: a bulk edit run without automation. The operation remembers it, so
-- the worker runs its items inside attome_core::quiet_scope, and each change
-- event those items write is marked quiet: workflow entry triggers and
-- follower notifications skip it, every other consumer reads it as usual.
-- Constant defaults, so adding the columns rewrites nothing.
SET LOCAL lock_timeout = '5s';

ALTER TABLE automation_bulk_operation
    ADD COLUMN IF NOT EXISTS quiet boolean NOT NULL DEFAULT false;

ALTER TABLE entity_change_event
    ADD COLUMN IF NOT EXISTS quiet boolean NOT NULL DEFAULT false;

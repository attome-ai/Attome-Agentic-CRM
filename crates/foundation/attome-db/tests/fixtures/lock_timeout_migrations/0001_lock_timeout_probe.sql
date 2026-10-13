-- Fixture migration for tests/migration_lock_timeout.rs — NOT a platform
-- migration and never applied to a real deployment (it is compiled only into
-- that test binary, via its own `sqlx::migrate!("tests/fixtures/...")`).
--
-- `ALTER TABLE` takes ACCESS EXCLUSIVE, which conflicts with the ACCESS SHARE
-- an ordinary `SELECT` holds for the life of its transaction. That is the
-- cheapest faithful reproduction of F-003's real shape: a schema change
-- queued behind a long-running read, with every subsequent write queued
-- behind the schema change.
ALTER TABLE lock_timeout_victim ADD COLUMN probe integer;

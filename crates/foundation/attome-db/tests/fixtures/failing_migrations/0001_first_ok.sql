-- P0-5 (BDB-F14): the first migration succeeds; the second fails, so the
-- pinned session still holds sqlx's migrator advisory lock when
-- `run_migrations` returns the error. The test asserts that session never
-- re-enters the pool.
CREATE TABLE migrator_failure_probe (id integer PRIMARY KEY);

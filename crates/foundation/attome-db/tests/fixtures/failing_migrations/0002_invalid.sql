-- A migration whose SQL fails at execution time (not a lock conflict, so
-- `run_migrations` returns immediately without its own unlock path).
SELECT * FROM migrator_failure_probe_table_that_does_not_exist;

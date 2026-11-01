-- T7-T4: an acceptance script (a customer test with a checklist) is run by a
-- person, who marks each step; the run keeps who ran it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE customer_test_run
    ADD COLUMN IF NOT EXISTS run_by uuid;

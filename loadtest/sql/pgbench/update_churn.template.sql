-- pgbench custom script — sustained UPDATE churn against a mutable-class
-- table, simulating the row_version bump every entity UPDATE does (D-037).
-- __TABLE__ is substituted by bloat-measurement.ps1 before use; :maxseq is
-- passed via pgbench -D.
\set target random(1, :maxseq)
UPDATE bloat_test.__TABLE__ SET row_version = row_version + 1, modified_at = now(), payload = payload WHERE seq_id = :target;

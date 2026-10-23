-- L6-T2: a profile states how many rows its statistics came from and
-- whether it read the whole table. Older profiles read every row one query
-- at a time and keep NULL.
ALTER TABLE data_profile ADD COLUMN IF NOT EXISTS sample_size bigint;
ALTER TABLE data_profile ADD COLUMN IF NOT EXISTS full_scan boolean NOT NULL DEFAULT false;

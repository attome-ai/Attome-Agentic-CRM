-- L6-T6: a data profile of an import's staged rows names the import.
ALTER TABLE data_profile ADD COLUMN IF NOT EXISTS import_job_ref uuid;

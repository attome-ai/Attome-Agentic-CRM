-- L3-T5: a data domain whose entities change only with its owners' or
-- stewards' approval at publish.
ALTER TABLE data_domain ADD COLUMN IF NOT EXISTS governed_change boolean NOT NULL DEFAULT false;

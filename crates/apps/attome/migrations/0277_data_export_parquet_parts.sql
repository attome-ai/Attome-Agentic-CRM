-- A23-T10: an export may be Parquet, split into parts of `split_rows` rows,
-- with its CSV or XLSX headers in the requester's language (`labels`).
-- `parts` lists every part as [{object_key, row_count, checksum}];
-- `object_key` and `checksum` stay the first part's, so a reader that knows
-- one file still finds it.
SET LOCAL lock_timeout = '5s';

ALTER TABLE data_export DROP CONSTRAINT IF EXISTS data_export_format_check;
ALTER TABLE data_export ADD CONSTRAINT data_export_format_check
    CHECK (format = ANY (ARRAY['csv'::text, 'xlsx'::text, 'json'::text, 'parquet'::text]));

ALTER TABLE data_export
    ADD COLUMN IF NOT EXISTS labels boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS split_rows bigint NULL,
    ADD COLUMN IF NOT EXISTS parts jsonb NULL;

ALTER TABLE data_export DROP CONSTRAINT IF EXISTS data_export_split_rows_check;
ALTER TABLE data_export ADD CONSTRAINT data_export_split_rows_check
    CHECK (split_rows IS NULL OR split_rows > 0);

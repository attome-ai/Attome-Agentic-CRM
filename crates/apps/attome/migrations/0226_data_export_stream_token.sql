-- L7-T5: the change-stream cursor that continues from an export's snapshot.
ALTER TABLE data_export ADD COLUMN IF NOT EXISTS stream_token text;

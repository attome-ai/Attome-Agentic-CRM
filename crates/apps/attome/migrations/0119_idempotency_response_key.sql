-- S9-T3: the id of the key that sealed a durable idempotency record's stored
-- response (idempotency.response_encryption_key). NULL means the body is
-- stored as it is: a row written before a key was configured, or on a
-- deployment without one.
ALTER TABLE idempotency_record ADD COLUMN IF NOT EXISTS response_key_id text;

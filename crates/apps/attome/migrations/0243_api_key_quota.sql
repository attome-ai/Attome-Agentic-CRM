-- S10-T1: an optional per-key request budget. NULL leaves the key under the
-- deployment's per-category limits only; a value adds a per-minute budget
-- across every route the key calls, enforced by the rate limiter.
ALTER TABLE api_key ADD COLUMN IF NOT EXISTS requests_per_minute integer;
ALTER TABLE api_key DROP CONSTRAINT IF EXISTS api_key_requests_per_minute_positive;
ALTER TABLE api_key ADD CONSTRAINT api_key_requests_per_minute_positive
    CHECK (requests_per_minute IS NULL OR requests_per_minute > 0);

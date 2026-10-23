-- M13-T2: a static header a webhook target wants on every delivery (an API
-- key, a bearer token). The value is encrypted under
-- `events.webhook_signing_key`, bound to its row like the signing secret
-- (Q18-T2), and never returned by the API.
ALTER TABLE event_subscription ADD COLUMN IF NOT EXISTS target_auth_header text;
ALTER TABLE event_subscription ADD COLUMN IF NOT EXISTS target_auth_value_encrypted text;

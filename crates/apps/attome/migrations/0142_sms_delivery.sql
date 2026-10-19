-- J4-T1: the SMS delivery ledger. One row per message sent through an SMS
-- provider (Twilio, Unifonic): who it went to, how many segments it took,
-- and its delivery state as the provider's receipts report it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS sms_delivery (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    provider text NOT NULL CHECK (provider IN ('twilio', 'unifonic')),
    provider_message_id text,
    recipient text NOT NULL,
    recipient_user_ref uuid,
    sender text,
    segments integer NOT NULL CHECK (segments >= 1),
    encoding text NOT NULL CHECK (encoding IN ('gsm7', 'ucs2')),
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'sent', 'delivered', 'undelivered', 'failed')),
    error_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sms_delivery_provider_message_idx
    ON sms_delivery (provider, provider_message_id) WHERE provider_message_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS sms_delivery_created_idx ON sms_delivery (created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON sms_delivery TO attome_runtime;
GRANT SELECT ON sms_delivery TO attome_readonly;

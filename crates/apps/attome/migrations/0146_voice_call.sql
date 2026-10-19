-- J6-T1: one row per phone call through a voice system (Twilio Voice or a
-- PBX). It ties the provider's call id to the phone_call activity logged for
-- it and keeps where the call is, so repeated or out-of-order provider
-- callbacks move it forward only, and the activity is completed once.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS voice_call (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    system_id uuid NOT NULL,
    provider_call_id text,
    user_id uuid REFERENCES user_account (id) ON DELETE SET NULL,
    activity_id uuid,
    direction text NOT NULL CHECK (direction IN ('inbound', 'outbound')),
    from_number text,
    to_number text,
    state text NOT NULL DEFAULT 'placing'
        CHECK (state IN ('placing', 'ringing', 'answered', 'ended', 'missed', 'failed')),
    answered_at timestamptz,
    ended_at timestamptz,
    duration_seconds integer,
    recording_url text,
    activity_done boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (system_id, provider_call_id)
);
CREATE INDEX IF NOT EXISTS voice_call_user_idx ON voice_call (user_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON voice_call TO attome_runtime;
GRANT SELECT ON voice_call TO attome_readonly;

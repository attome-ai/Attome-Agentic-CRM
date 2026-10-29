-- N18-T1: the bot runtime (attome_ai::bot) answers on WhatsApp and SMS as
-- well as web chat, so a conversation's surface may name either.
ALTER TABLE ai_conversation DROP CONSTRAINT IF EXISTS ai_conversation_surface_known;
ALTER TABLE ai_conversation ADD CONSTRAINT ai_conversation_surface_known
    CHECK (surface IN ('internal', 'webchat', 'mcp', 'workflow', 'whatsapp', 'sms'));

-- One person's conversation with a channel's bot: the agent session that
-- answers them, the last inbound message answered (a retried reply job finds
-- it and does nothing), and when it was handed to a person (the bot is then
-- silent on that thread). Keyed by the channel's system and the person's
-- record.
CREATE TABLE IF NOT EXISTS bot_thread (
    integration_system_id uuid NOT NULL,
    party_entity text NOT NULL,
    party_id uuid NOT NULL,
    channel text NOT NULL CHECK (channel IN ('whatsapp', 'sms')),
    agent_session_id uuid NOT NULL,
    last_message_id text,
    handed_off_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (integration_system_id, party_entity, party_id)
);

GRANT SELECT, INSERT, UPDATE ON bot_thread TO attome_runtime;

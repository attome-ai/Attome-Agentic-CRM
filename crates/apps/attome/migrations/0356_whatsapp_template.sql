-- J5-T3: a WhatsApp number's approved message templates, synced from Meta,
-- each with the variables its components take and the attribute that fills
-- each one. A number is an integration system with "social": "whatsapp".
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS whatsapp_template (
    id           uuid        PRIMARY KEY DEFAULT uuidv7(),
    system_id    uuid        NOT NULL,
    name         text        NOT NULL,
    language     text        NOT NULL,
    category     text        NOT NULL DEFAULT '',
    components   jsonb       NOT NULL DEFAULT '[]',
    variables    text[]      NOT NULL DEFAULT '{}',
    variable_map jsonb       NOT NULL DEFAULT '{}',
    synced_at    timestamptz NOT NULL DEFAULT now(),
    row_version  bigint      NOT NULL DEFAULT 0,
    UNIQUE (system_id, name, language)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON whatsapp_template TO attome_runtime;
GRANT SELECT ON whatsapp_template TO attome_readonly;

-- E18-T1: social listening mentions (Brandwatch), one row per mention of a
-- configured query, with the provider's sentiment label and the
-- deployment's own (N19, scored locally when fetched).
CREATE TABLE IF NOT EXISTS social_mention (
    id                 uuid        PRIMARY KEY DEFAULT uuidv7(),
    system_id          uuid        NOT NULL,
    query_id           text        NOT NULL,
    guid               text        NOT NULL,
    url                text,
    title              text,
    snippet            text,
    author             text,
    domain             text,
    language           text,
    published_at       timestamptz,
    provider_sentiment text,
    sentiment          text        NOT NULL CHECK (sentiment IN ('positive', 'neutral', 'negative')),
    sentiment_score    real        NOT NULL,
    fetched_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (system_id, query_id, guid)
);
CREATE INDEX IF NOT EXISTS social_mention_published_idx
    ON social_mention (system_id, query_id, published_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON social_mention TO attome_runtime;
GRANT SELECT ON social_mention TO attome_readonly;

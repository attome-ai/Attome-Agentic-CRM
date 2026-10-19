-- N22-T2: a recording's transcript, keyed by the file's storage key like
-- `document_text`. Served to anyone who may read a document naming the file;
-- removed with the last such document (attome_document::transcribe).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS recording_transcript (
    file_key text PRIMARY KEY,
    content_text text NOT NULL,
    language text,
    duration_seconds double precision,
    -- [{start, end, text}], seconds from the start.
    segments jsonb NOT NULL DEFAULT '[]',
    model text NOT NULL,
    transcribed_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON recording_transcript TO attome_runtime;
GRANT SELECT ON recording_transcript TO attome_readonly;

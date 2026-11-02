-- D22-T5 (V2-D1588 (3)): the redacted copy of a call's transcript that call
-- analysis reads, one per analysis: emails, phone numbers and IBANs masked,
-- each segment with its speaker as the speech endpoint labelled it. The raw
-- transcript stays in recording_transcript and analysis never reads it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS call_transcript_redacted (
    analysis_id uuid PRIMARY KEY,
    -- [{start_ms, end_ms, speaker, text}]
    segments jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON call_transcript_redacted TO attome_runtime;
GRANT SELECT ON call_transcript_redacted TO attome_readonly;

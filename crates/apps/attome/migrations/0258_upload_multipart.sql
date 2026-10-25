-- Z6-T2: an upload session can arrive in parts. The parts are objects beside
-- the session's quarantine key, so an interrupted upload resumes from the
-- parts that arrived; completing assembles them into the quarantine object,
-- and the session's ordinary finalize and scan take it from there. An open
-- multipart upload lives 24 hours instead of the session's short TTL.
CREATE TABLE IF NOT EXISTS upload_multipart (
    session_id uuid PRIMARY KEY REFERENCES upload_session (id) ON DELETE CASCADE,
    part_size bigint NOT NULL CHECK (part_size > 0),
    part_count integer NOT NULL CHECK (part_count BETWEEN 1 AND 10000),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'assembled', 'aborted')),
    checksum_sha256 text,
    created_at timestamptz NOT NULL DEFAULT now(),
    assembled_at timestamptz
);

CREATE INDEX IF NOT EXISTS upload_multipart_open_idx
    ON upload_multipart (created_at) WHERE status = 'open';

GRANT SELECT, INSERT, UPDATE, DELETE ON upload_multipart TO attome_runtime;
GRANT SELECT ON upload_multipart TO attome_readonly;

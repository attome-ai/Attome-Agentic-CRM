-- AB8-T6: each platform upgrade: versions, who started it, the safety point
-- to go back to, the pre-upgrade check report, the verification's evidence
-- and how it ended.
CREATE TABLE IF NOT EXISTS ops_upgrade (
    id uuid PRIMARY KEY,
    from_version text,
    to_version text,
    started_by uuid,
    started_at timestamptz,
    finished_at timestamptz,
    status text NOT NULL CHECK (status IN ('started', 'verified', 'failed', 'rolled_back')),
    safety_point text,
    check_report jsonb,
    verification_evidence_id uuid,
    contract_applied_at timestamptz,
    row_version bigint NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS ops_upgrade_started_idx ON ops_upgrade (started_at DESC);

GRANT SELECT, INSERT, UPDATE ON ops_upgrade TO attome_runtime;
GRANT SELECT ON ops_upgrade TO attome_readonly;

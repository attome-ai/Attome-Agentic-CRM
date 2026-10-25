-- AB4-T6: every recovery drill's signed evidence (attome-evidence/v1), kept
-- in the deployment it proves. Uploaded once (the evidence's SHA-256 is
-- unique), never edited, and not deletable for 400 days.
CREATE TABLE IF NOT EXISTS ops_drill_run (
    id uuid PRIMARY KEY,
    kind text NOT NULL,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    overall_ok boolean NOT NULL,
    restore_ok boolean NOT NULL,
    provenance_ok boolean NOT NULL,
    rpo_seconds double precision,
    rto_seconds double precision,
    data_size_bytes bigint,
    platform_version text NOT NULL,
    key_id text NOT NULL,
    sha256 text NOT NULL UNIQUE,
    evidence jsonb NOT NULL,
    uploaded_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ops_drill_run_kind_idx ON ops_drill_run (kind, finished_at DESC);

CREATE OR REPLACE FUNCTION ops_drill_run_keep() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'ops_drill_run is append-only';
    END IF;
    IF OLD.created_at > now() - interval '400 days' THEN
        RAISE EXCEPTION 'drill evidence is kept for 400 days';
    END IF;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS ops_drill_run_keep ON ops_drill_run;
CREATE TRIGGER ops_drill_run_keep BEFORE UPDATE OR DELETE ON ops_drill_run
    FOR EACH ROW EXECUTE FUNCTION ops_drill_run_keep();

GRANT SELECT, INSERT ON ops_drill_run TO attome_runtime;
GRANT SELECT ON ops_drill_run TO attome_readonly;

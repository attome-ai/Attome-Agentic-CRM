-- A24-T5: the imports a migration wave queued, for its compare report and
-- its rollback. An import belongs to the first wave that queued it (a later
-- wave sending identical rows reuses that import), so rolling a wave back
-- never takes back an earlier wave's work. `rolled_back` is a wave whose
-- imports were taken back.
CREATE TABLE IF NOT EXISTS migration_wave_import (
    import_job_id uuid PRIMARY KEY REFERENCES import_job (id),
    wave_id uuid NOT NULL REFERENCES migration_wave (id) ON DELETE CASCADE,
    entity text NOT NULL,
    seq integer NOT NULL
);

CREATE INDEX IF NOT EXISTS migration_wave_import_wave_idx ON migration_wave_import (wave_id, seq);

ALTER TABLE migration_wave DROP CONSTRAINT IF EXISTS migration_wave_status_check;
ALTER TABLE migration_wave ADD CONSTRAINT migration_wave_status_check
    CHECK (status IN ('queued', 'running', 'loaded', 'failed', 'rolled_back'));

GRANT SELECT, INSERT, UPDATE, DELETE ON migration_wave_import TO attome_runtime;
GRANT SELECT ON migration_wave_import TO attome_readonly;

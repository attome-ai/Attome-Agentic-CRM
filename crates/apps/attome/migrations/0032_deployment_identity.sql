-- Y5-T2: one id per deployment, made once by the first server to boot, which
-- every node writes into the shared cache as a marker. A second deployment
-- pointed at the same cache finds another id there and refuses to start.
CREATE TABLE IF NOT EXISTS deployment_identity (
    id uuid PRIMARY KEY,
    singleton boolean NOT NULL DEFAULT true UNIQUE CHECK (singleton),
    created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON deployment_identity TO attome_runtime;
GRANT SELECT ON deployment_identity TO attome_readonly;

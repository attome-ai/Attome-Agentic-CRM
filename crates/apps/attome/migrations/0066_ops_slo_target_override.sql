-- AA13-T8: a deployment's own latency targets for an SLO class, within
-- bounds of the reference targets in observability/slo-catalogue.json.
-- Absent row: the reference target applies.

CREATE TABLE IF NOT EXISTS ops_slo_target_override (
    class_id text NOT NULL PRIMARY KEY,
    p95_ms integer NOT NULL,
    p99_ms integer NOT NULL,
    row_version bigint NOT NULL DEFAULT 1,
    updated_by uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ops_slo_target_override_positive CHECK (p95_ms > 0 AND p99_ms >= p95_ms)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ops_slo_target_override TO attome_runtime;
GRANT SELECT ON ops_slo_target_override TO attome_readonly;

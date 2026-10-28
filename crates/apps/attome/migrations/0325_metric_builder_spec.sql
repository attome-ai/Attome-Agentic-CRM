-- P7-T2: the spec a builder metric (P9-T3) was last built from. The metric's
-- stored query holds only the aggregate; keeping the spec lets a dashboard
-- drill list the records behind the value. One row per metric, replaced on
-- every build; owned by attome-metric.
CREATE TABLE IF NOT EXISTS metric_builder_spec (
    metric_ref uuid PRIMARY KEY,
    spec jsonb NOT NULL,
    updated_by uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE ON metric_builder_spec TO attome_runtime;
GRANT SELECT ON metric_builder_spec TO attome_readonly;

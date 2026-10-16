-- Y2-T8: one sample per entity table and day (live rows and total size), so
-- the table-health report can show growth. Filled by a daily job from the
-- statistics views; holds no business data.

CREATE TABLE IF NOT EXISTS table_health_sample (
    entity text NOT NULL,
    sampled_on date NOT NULL,
    live_rows bigint NOT NULL,
    total_bytes bigint NOT NULL,
    PRIMARY KEY (entity, sampled_on)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON table_health_sample TO attome_runtime;
GRANT SELECT ON table_health_sample TO attome_readonly;

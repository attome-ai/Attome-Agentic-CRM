-- M11-T1: where each round-robin assign node left off, per published graph
-- version and node, so the next record goes to the next person even across
-- restarts and nodes of the cluster.
CREATE TABLE IF NOT EXISTS workflow_assign_cursor (
    definition_version_id uuid NOT NULL,
    node_id text NOT NULL,
    last_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (definition_version_id, node_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON workflow_assign_cursor TO attome_runtime;
GRANT SELECT ON workflow_assign_cursor TO attome_readonly;

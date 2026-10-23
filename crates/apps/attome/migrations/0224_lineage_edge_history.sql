-- L5-T4: lineage edges a publish replaced, with the graph versions they
-- were valid in ([valid_from, valid_to)), so the graph can be read as of a
-- version and two versions compared.
CREATE TABLE IF NOT EXISTS lineage_edge_history (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    from_kind text NOT NULL,
    from_ref uuid NOT NULL,
    from_label text NOT NULL DEFAULT '',
    to_kind text NOT NULL DEFAULT 'entity',
    to_ref uuid,
    to_entity text NOT NULL,
    to_attribute text NOT NULL DEFAULT '',
    edge_kind text NOT NULL,
    confidence text NOT NULL,
    valid_from bigint NOT NULL,
    valid_to bigint NOT NULL
);

CREATE INDEX IF NOT EXISTS lineage_edge_history_valid_idx
    ON lineage_edge_history (valid_from, valid_to);

GRANT SELECT, INSERT ON lineage_edge_history TO attome_runtime;
GRANT SELECT ON lineage_edge_history TO attome_readonly;

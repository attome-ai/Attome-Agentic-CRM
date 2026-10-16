-- L5-T1: metadata references become a versioned lineage graph. Each edge
-- says how the source uses the target (reads, writes, derives, triggers),
-- how sure the parser is (parsed, entity_only, hand), and the graph version
-- of the publish that produced it; a person can document a hand-made edge.
-- `to_attribute` already holds the attribute-level target.
ALTER TABLE metadata_reference
    ADD COLUMN IF NOT EXISTS edge_kind text NOT NULL DEFAULT 'reads'
        CHECK (edge_kind IN ('reads', 'writes', 'derives', 'triggers')),
    ADD COLUMN IF NOT EXISTS confidence text NOT NULL DEFAULT 'parsed'
        CHECK (confidence IN ('parsed', 'entity_only', 'hand')),
    ADD COLUMN IF NOT EXISTS graph_version bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS documented_by uuid,
    ADD COLUMN IF NOT EXISTS note text;

CREATE INDEX IF NOT EXISTS metadata_reference_target_idx
    ON metadata_reference (to_entity, to_attribute);
CREATE INDEX IF NOT EXISTS metadata_reference_source_idx
    ON metadata_reference (from_kind, from_ref);

-- One row per publish that changed the graph.
CREATE TABLE IF NOT EXISTS lineage_version (
    version bigint PRIMARY KEY,
    published_at timestamptz NOT NULL DEFAULT now(),
    changeset_ref uuid
);

-- Systems outside the deployment that data flows to or from.
CREATE TABLE IF NOT EXISTS lineage_system (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL UNIQUE,
    kind text NOT NULL,
    direction text NOT NULL CHECK (direction IN ('inbound', 'outbound', 'both'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON lineage_version, lineage_system TO attome_runtime;
GRANT SELECT ON lineage_version, lineage_system TO attome_readonly;

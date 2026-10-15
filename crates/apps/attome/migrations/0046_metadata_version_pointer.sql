-- Y8-T3: which metadata version is current, and which version each node has
-- switched to. A publish records its version and manifest hash; the current
-- pointer moves to it; each node writes a row when it has switched, so a
-- change that removes old structure can wait until every node is past it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS metadata_published_version (
    version bigint PRIMARY KEY,
    manifest_hash text NOT NULL,
    published_by uuid,
    published_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS metadata_current (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version bigint NOT NULL REFERENCES metadata_published_version(version),
    switched_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS metadata_node_switch (
    node_id text NOT NULL CHECK (char_length(node_id) BETWEEN 1 AND 300),
    version bigint NOT NULL,
    switched_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, version)
);

GRANT SELECT, INSERT ON metadata_published_version TO attome_runtime;
GRANT SELECT, INSERT, UPDATE ON metadata_current TO attome_runtime;
GRANT SELECT, INSERT ON metadata_node_switch TO attome_runtime;
GRANT SELECT ON metadata_published_version, metadata_current, metadata_node_switch TO attome_readonly;

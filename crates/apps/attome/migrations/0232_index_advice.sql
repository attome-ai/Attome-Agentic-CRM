-- AA3-T1: the attributes the index advisor chose to index (from what views
-- and definitions filter and sort on); the attribute-index job counts them
-- as wanted.
CREATE TABLE IF NOT EXISTS index_advice (
    entity_logicalname text NOT NULL,
    attribute text NOT NULL,
    uses integer NOT NULL DEFAULT 0,
    advised_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (entity_logicalname, attribute)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON index_advice TO attome_runtime;
GRANT SELECT ON index_advice TO attome_readonly;

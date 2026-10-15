-- A25-T1: search settings an administrator tunes without code: how each
-- attribute takes part in search (an exact key, full text, or not at all)
-- and its weight; per entity whether it is searched, how far back, its boost
-- and whether images or documents get embeddings; synonyms, stop words and
-- results pinned to a query.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS search_attribute_setting (
    entity_logicalname text NOT NULL,
    attribute_logicalname text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('key', 'text', 'off')),
    weight real NOT NULL DEFAULT 1.0 CHECK (weight >= 0 AND weight <= 10),
    row_version bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (entity_logicalname, attribute_logicalname)
);

CREATE TABLE IF NOT EXISTS search_entity_setting (
    entity_logicalname text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT true,
    max_age_days integer CHECK (max_age_days IS NULL OR max_age_days > 0),
    image_embedding boolean NOT NULL DEFAULT false,
    document_embedding boolean NOT NULL DEFAULT false,
    boost real NOT NULL DEFAULT 1.0 CHECK (boost >= 0 AND boost <= 10),
    row_version bigint NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS search_synonym (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    terms text[] NOT NULL CHECK (cardinality(terms) >= 2),
    lang text,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS search_synonym_terms_idx ON search_synonym USING gin (terms);

CREATE TABLE IF NOT EXISTS search_stopword (
    word text PRIMARY KEY,
    lang text NOT NULL
);

CREATE TABLE IF NOT EXISTS search_pin (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    query_norm text NOT NULL,
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    position integer NOT NULL DEFAULT 1 CHECK (position >= 1),
    UNIQUE (query_norm, entity_logicalname, record_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON search_attribute_setting, search_entity_setting,
    search_synonym, search_stopword, search_pin TO attome_runtime;
GRANT SELECT ON search_attribute_setting, search_entity_setting, search_synonym,
    search_stopword, search_pin TO attome_readonly;

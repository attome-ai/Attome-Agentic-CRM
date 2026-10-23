-- N15-T2: records, timeline items and documents as retrievable passages,
-- chunked by structure from the change feed (consumer
-- `attome-search/record-chunks`). `source_*` is the record a chunk came
-- from; `entity_logicalname`/`record_id` the record it belongs to (the
-- source, or the record a timeline item is attached to). A reader passes
-- both record checks. The vector is filled in after the text, outside any
-- transaction, and cleared whenever the text changes.
CREATE TABLE IF NOT EXISTS record_chunk (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    source_entity text NOT NULL,
    source_id uuid NOT NULL,
    ordinal integer NOT NULL,
    heading_path text[] NOT NULL DEFAULT ARRAY[]::text[],
    text_display text NOT NULL,
    tsv tsvector NOT NULL,
    content_hash bytea,
    embedding halfvec(1024),
    embedding_model varchar(128),
    embedding_locality text,
    indexed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT record_chunk_source_ordinal UNIQUE (source_entity, source_id, ordinal)
);

CREATE INDEX IF NOT EXISTS record_chunk_owner_idx ON record_chunk (entity_logicalname, record_id);
CREATE INDEX IF NOT EXISTS record_chunk_tsv_idx ON record_chunk USING gin (tsv);
CREATE INDEX IF NOT EXISTS record_chunk_unembedded_idx ON record_chunk (id) WHERE embedding IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON record_chunk TO attome_runtime;
GRANT SELECT ON record_chunk TO attome_readonly;

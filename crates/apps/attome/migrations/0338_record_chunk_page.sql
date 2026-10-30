-- A25-T6: the page of a document a passage came from, so a search result
-- opens the file at it (attome_document::text_extract::pages). NULL for a
-- passage of a record's own fields, and for a file with no pages.
-- The vector index serves POST /api/v1/search/similar (nearest passages).
-- record_chunk is written only by the search drain, so the short write lock
-- of a plain CREATE INDEX holds back nothing a user waits on.
SET LOCAL lock_timeout = '5s';

ALTER TABLE record_chunk ADD COLUMN IF NOT EXISTS page integer
    CHECK (page IS NULL OR page > 0);

CREATE INDEX IF NOT EXISTS record_chunk_embedding_hnsw ON record_chunk
    USING hnsw (embedding halfvec_cosine_ops) WHERE (embedding IS NOT NULL);

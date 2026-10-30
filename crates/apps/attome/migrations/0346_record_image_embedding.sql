-- A25-T6 (V2-D1429): image search. Each image file of a document attached to
-- a record of an entity whose search setting `image_embedding` is on gets
-- one vector from the image-text model (`inference.image_embedding`,
-- SigLIP 2). The vector's size is the model's, so the column has none; a
-- search compares only vectors of the configured model, of its size.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS record_image_embedding (
    -- The document (`attome_document`) and the stored file it names.
    source_id uuid NOT NULL,
    file_key text NOT NULL,
    embedding_model text NOT NULL,
    -- The record the document is attached to: its visibility is the image's.
    entity_logicalname text NOT NULL,
    record_id uuid NOT NULL,
    -- NULL when the file could not be embedded (not an image the model
    -- reads, too large, or on a field labelled sensitive): `skipped` says
    -- why, and the file is not tried again until it changes.
    embedding vector,
    skipped text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, file_key, embedding_model)
);

CREATE INDEX IF NOT EXISTS record_image_embedding_model
    ON record_image_embedding (embedding_model, entity_logicalname);

GRANT SELECT, INSERT, UPDATE, DELETE ON record_image_embedding TO attome_runtime;
GRANT SELECT ON record_image_embedding TO attome_readonly;

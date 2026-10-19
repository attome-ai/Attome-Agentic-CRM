-- K1-T4: the text extracted from a clean upload, keyed by its storage key.
-- Global search appends it to the projection of every `attome_document`
-- naming the file, so the text is searchable with the document's own
-- permissions. Derived and rebuildable: extraction rewrites it.
CREATE TABLE IF NOT EXISTS document_text (
    file_key text PRIMARY KEY,
    format text NOT NULL,
    content_text text NOT NULL,
    extracted_at timestamp with time zone DEFAULT now() NOT NULL
);
